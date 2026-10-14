#!/usr/bin/env python3
"""Execute native sabm nine-slice geometry against a guarded framebuffer.

The kernel BMP parser is real. Pixel decoding/memory/kernel allocation are
modeled; the firmware's clipping and nine-slice loops execute unchanged.
"""
import argparse
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *
from check_highlight import ROOT, BASE, RAM, Phone


def render(blob, width=240, height=30, clipped=False):
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    u.mem_map(BASE,0x800000)
    u.mem_write(BASE,(ROOT/"backup/l728-user-ecc.bin").read_bytes())
    u.mem_map(0x809c5000,0xc10000)
    u.mem_write(0x809c5e00,(ROOT/"backup/l728-kernel-ecc.bin").read_bytes())
    u.mem_map(RAM,0x100000)
    u.mem_map(0x100000,0x10000)
    stack,stop=0x10f000,0x100100
    image,area,source,pixels=RAM+0x1000,RAM+0x2000,RAM+0x2010,RAM+0x10000
    output=RAM+0x2100
    u.mem_write(image,blob)
    bmp_offset=12 if blob[:4]==b"sabm" else 0
    bmp=blob[bmp_offset:]
    assert bmp[:2]==b"BM"
    # Actual kernel BMP metadata/mask parser, with no substituted boundaries.
    u.reg_write(UC_ARM_REG_R0,image+bmp_offset)
    u.reg_write(UC_ARM_REG_R1,output)
    u.reg_write(UC_ARM_REG_SP,stack)
    u.reg_write(UC_ARM_REG_LR,stop|1)
    u.emu_start(0x80bf1db9,stop,count=10000)
    assert u.reg_read(UC_ARM_REG_PC)==stop and u.reg_read(UC_ARM_REG_R0)==0
    assert struct.unpack("<3I",u.mem_read(output+8,12))==(0xf800,0x7e0,0x1f)
    iw,ih=struct.unpack("<2H",u.mem_read(output+20,4))
    assert (iw,ih)==(1,144)
    color=struct.unpack_from("<H",bmp,66)[0]
    clip=(13,7,width-18,height-6) if clipped else (0,0,width-1,height-1)
    u.mem_write(area,struct.pack("<4h",*clip))
    u.mem_write(source,struct.pack("<4h",*clip))
    u.mem_write(pixels,b"\x5a"*(width*height*4+32))
    heap=RAM+0x40000
    stopped=False
    spans=[]
    def read32(a):return struct.unpack("<I",u.mem_read(a,4))[0]
    def ret(value=0):
        u.reg_write(UC_ARM_REG_R0,value)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def boundary(uc,a,size,data):
        nonlocal heap,stopped
        r=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
        sp=uc.reg_read(UC_ARM_REG_SP)
        if a==stop:
            stopped=True;uc.emu_stop();return
        if a==0x88091b90:raise AssertionError("Native background assert")
        if a in (0x88091bf8,0x88091b60):
            result=heap;heap=(heap+r[0]+7)&~7;ret(result)
        elif a in (0x88091c08,0x88091c18):
            uc.mem_write(r[0],bytes(r[1]));ret(r[0])
        elif a in (0x88091c10,0x88091c20):
            uc.mem_write(r[0],bytes(uc.mem_read(r[1],r[2])));ret(r[0])
        elif a==0x88091bf0:ret()
        elif a==0x880912e8:
            # Model decoding the embedded BMP to native ARGB scratch pixels.
            desc=r[0]
            assert read32(desc)==image+12
            target=read32(r[1])
            assert struct.unpack("<2H",uc.mem_read(target+8,4))==(1,144)
            uc.mem_write(read32(target+12),struct.pack("<I",0xff000000|color)*144)
            ret()
        elif a in callbacks:
            # Native geometry chooses these row/column/pixel operations.
            if a==callbacks[0]:
                addresses=[r[0]+4*i for i in range(r[3]-r[2]+1)]
            elif a==callbacks[1]:
                addresses=[r[0]+4*r[1]*i for i in range(read32(sp)-r[3]+1)]
            else:addresses=[r[0]]
            for dest in addresses:
                assert pixels<=dest<pixels+width*height*4
                index=(dest-pixels)//4
                x,y=index%width,index//width
                assert clip[0]<=x<=clip[2] and clip[1]<=y<=clip[3],(x,y,clip)
                uc.mem_write(dest,struct.pack("<I",color))
                spans.append(index)
            ret()
    table=0x883db3e8 # mode=1, native LCD format flag at 0x81709984 is zero
    callbacks=[read32(table+4*i)&~1 for i in range(3)]
    for a in (stop,0x88091b90,0x88091bf8,0x88091b60,0x88091bf0,
              0x88091c08,0x88091c18,0x88091c10,0x88091c20,0x880912e8,*callbacks):
        u.hook_add(UC_HOOK_CODE,boundary,begin=a,end=a)
    # sabm public renderer: destination, clip/source, LCD dimensions and pixels.
    for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),
                         (1,image,len(blob),area)):
        u.reg_write(reg,value)
    u.mem_write(stack,struct.pack("<5I",0,source,width,height,pixels))
    u.reg_write(UC_ARM_REG_SP,stack)
    u.reg_write(UC_ARM_REG_LR,stop|1)
    u.emu_start(0x881ac3e5,0,count=500000)
    assert stopped and u.reg_read(UC_ARM_REG_SP)==stack
    assert u.reg_read(UC_ARM_REG_R0)==1
    expected={y*width+x for y in range(clip[1],clip[3]+1) for x in range(clip[0],clip[2]+1)}
    assert set(spans)==expected,(len(set(spans)),len(expected))
    assert bytes(u.mem_read(pixels+width*height*4,32))==b"\x5a"*32


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder",type=Path,required=True)
    args=parser.parse_args()
    folder=args.folder.resolve()
    report=json.loads((folder/"manifest.json").read_text())
    image=(folder/"l728-user-highlight-CANDIDATE.bin").read_bytes()
    # Reproduce the old plain-BMP branch without a private intermediate image.
    old_phone=Phone(image,report,b"L7H\x01\x01\x01\xa5\x5a")
    out=RAM+0x70000
    ptr=old_phone.call(0x881ed5c4,0x4000001f,0x90014,out)
    assert old_phone.call(0x88354cc0,ptr+12,642,out+16)==0
    old_phone.uc.mem_write(out+32,struct.pack("<4h",0,0,239,29))
    assert old_phone.call(0x88355350,1,144,out+32,out+48)==1
    assert struct.unpack("<4h",old_phone.uc.mem_read(out+48,8))==(0,0,0,29)
    for bg in range(1,7):
        phone=Phone(image,report,bytes((76,55,72,1,bg,1,bg^1^0xa5,0x5a)))
        ptr=phone.call(0x881ed5c4,0x4000001f,0x90014,out)
        blob=bytes(phone.uc.mem_read(ptr,phone.read32(out)))
        render(blob)
        render(blob,clipped=True)
    print("PASS: actual kernel BMP RGB565 parser; native sabm nine-slice fills all 240 columns; clipped draw stays inside bounds")
    checks=json.loads((folder/"checks.json").read_text())
    assert checks["output_sha256"]==report["output_sha256"]
    checks["native_background_geometry_checked"]=True
    (folder/"checks.json").write_text(json.dumps(checks,indent=2)+"\n")


if __name__=="__main__":main()
