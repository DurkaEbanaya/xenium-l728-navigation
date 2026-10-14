#!/usr/bin/env python3
"""Focused execution of candidate hooks, UI events and file failure handling.

Runs the real native RAM registry and hook trampolines. Filesystem, widgets
and LCD are modeled boundaries; this is not evidence of device compatibility.
"""
import hashlib
import json
from pathlib import Path
import struct
import argparse
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "experimental/highlight"
BASE = 0x88000000
RAM, STACK, STOP = 0x81700000, 0x10f000, 0x100100


class Phone:
    def __init__(self, image, manifest, record=None, native_services=()):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        for addr,size in ((BASE,0x800000),(RAM,0x100000),(0x100000,0x10000)):
            self.uc.mem_map(addr,size)
        self.uc.mem_map(0x81912000,0x6000)
        self.uc.mem_write(BASE,image)
        # Imported malloc is an ARM veneer. Execute it, and model only the
        # kernel allocator behind it; intercepting the veneer hid mode bugs.
        assert image[0x91b60:0x91b64] == bytes.fromhex("04f01fe5")
        self.allocator = struct.unpack_from("<I",image,0x91b64)[0]
        assert self.allocator == 0x81082409
        self.uc.mem_map(self.allocator & ~0xfff,0x1000)
        self.uc.hook_add(UC_HOOK_CODE,self.allocator_entry,begin=0x88091b60,end=0x88091b60)
        self.symbols = manifest["symbols"]
        self.heap = RAM + 0x80000
        self.record = record
        self.fail_save = False
        self.short_read = False
        self.fail_alloc = False
        self.focused = 0
        self.indices = {}
        self.items = {}
        self.captions = {}
        self.fills = []
        self.effects = []
        self.menu_color = None
        self.stopped = False
        self.original_image = 0x12345678
        # Native registry table and globals, from the actual firmware literals.
        source = (ROOT / "backup/l728-user-ecc.bin").read_bytes()
        table,glob = struct.unpack_from("<II",source,0x313554)
        assert table == 0x8191216c and glob == 0x817099ac
        for i in range(1500):
            slot = table + 12*i
            self.uc.mem_write(slot,struct.pack("<III",0,0,slot+12 if i<1499 else 0))
        self.uc.mem_write(glob,struct.pack("<III",0xff,table,0))
        self.glob = glob
        services = {STOP,self.allocator & ~1,0x88091b90,0x881d2d02,0x881d36ba,
            0x881d3710,0x881d366a,0x8831af24,0x881ecd68,0x8806d398,
            0x881ebc5a,0x883391e8,0x8806d3d6,0x8806d12c,0x8806d42c,
            0x8806d36a,0x8806d0dc,0x88229b70,0x880a0802,
            0x881e84f0,0x881e85de,0x88354260,0x881ed5cc,0x881ed670,
            0x880a328e,0x880a34cc,0x8806d6f8,0x8806d06c}
        services -= set(native_services)
        for addr in services:
            self.uc.hook_add(UC_HOOK_CODE,self.boundary,begin=addr,end=addr)

    def read32(self,addr):
        return struct.unpack("<I",self.uc.mem_read(addr,4))[0]

    def allocator_entry(self,uc,addr,size,data):
        assert not uc.reg_read(UC_ARM_REG_CPSR) & 0x20, "malloc ARM veneer entered in Thumb mode"

    def write32(self,addr,value):
        self.uc.mem_write(addr,struct.pack("<I",value))

    def text(self,ptr,n=None):
        if n is None:
            n=0
            while self.uc.mem_read(ptr+2*n,2)!=b"\0\0": n+=1
        return bytes(self.uc.mem_read(ptr,2*n)).decode("utf-16-le")

    def boundary(self,uc,addr,size,data):
        if addr==STOP:
            self.stopped=True
            uc.emu_stop()
            return
        r=[uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
        sp=uc.reg_read(UC_ARM_REG_SP)
        assert sp%8==0, (hex(addr),hex(sp))
        result=0
        if addr==0x88091b90:
            raise AssertionError("Native assertion fired")
        if addr==(self.allocator & ~1):
            assert uc.reg_read(UC_ARM_REG_CPSR) & 0x20, "kernel allocator must be Thumb"
            if not self.fail_alloc:
                result=self.heap
                self.heap=(self.heap+r[0]+7)&~7
        elif addr in (0x880a328e,0x880a34cc):
            self.menu_color=struct.unpack("<H",uc.mem_read(sp+20,2))[0]
            assert r==[0x123,0x124,0x125,0x126]
        elif addr==0x881d2d02:
            assert self.text(r[0])==r"D:\l728-highlight.cfg" and r[2:]==[0,0]
            assert r[1] in (0x31,0x52)
            self.effects.append(("open",r[1]))
            result=1 if r[1]==0x31 and self.record is not None else 2 if r[1]==0x52 and not self.fail_save else 0
        elif addr==0x881d36ba:
            assert r[0]==1 and r[2]==8 and self.read32(sp)==0
            content=self.record[:4] if self.short_read else self.record
            uc.mem_write(r[1],content)
            self.write32(r[3],len(content))
        elif addr==0x881d3710:
            assert r[0]==2 and r[2]==8 and self.read32(sp)==0
            self.record=bytes(uc.mem_read(r[1],r[2]))
            self.write32(r[3],r[2])
        elif addr==0x881d366a:
            self.effects.append(("close",r[0]))
        elif addr==0x8831af24:
            self.effects.append(("stock_event",r[1]))
            result=0x55
        elif addr==0x881ecd68: result=self.focused
        elif addr==0x8806d398: result=self.indices[r[0]]
        elif addr==0x883391e8:
            ptr,n=struct.unpack("<IH",uc.mem_read(r[1],6))
            self.captions[r[0]]=self.text(ptr,n)
        elif addr==0x8806d3d6:
            self.items[r[0]]=[]
        elif addr==0x8806d12c:
            kind,ptr,n=struct.unpack("<III",uc.mem_read(r[1],12))
            assert kind==1 and bytes(uc.mem_read(r[1]+12,48))==bytes(48)
            self.items[r[0]].append(self.text(ptr,n))
        elif addr==0x8806d36a: self.indices[r[0]]=r[1]
        elif addr==0x8806d6f8:
            assert r[0] in (0x9fe03,0x9fe06)
            result=RAM+0x71000+(r[0]==0x9fe06)*0x200
        elif addr==0x8806d06c:
            assert r[0] in (RAM+0x71000,RAM+0x71200) and r[2]==1
            ptr,n=struct.unpack("<IH",uc.mem_read(r[1],6))
            assert self.text(ptr,n) in ("Фон выделения","Буквы выделения")
        elif addr==0x8806d0dc:
            raise AssertionError("Synthetic title passed to native resource-ID helper")
        elif addr==0x880a0802:
            assert r[1:]==[0xf025,0,0]
            self.effects.append(("redraw",r[0]))
        elif addr==0x881e84f0:
            assert r[0] in (9,10,11)
            result=0xef9d
        elif addr==0x881e85de: result=7
        elif addr==0x88354260:
            assert r[0]==7
            self.fills.append((struct.unpack("<4h",struct.pack("<II",r[1],r[2])),r[3]))
        elif addr==0x881ed5cc:
            assert r[0]==0x4000001f and uc.reg_read(UC_ARM_REG_R4)==r[0]
            assert uc.reg_read(UC_ARM_REG_R6)==r[2]
            self.write32(r[2],48)
            # Model the rest of the stock function, after REAL transplanted prologue.
            self.pop([UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,
                      UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_PC])
            uc.reg_write(UC_ARM_REG_R0,self.original_image)
            return
        elif addr==0x881ed670:
            assert uc.reg_read(UC_ARM_REG_R4)==r[0]
            assert uc.reg_read(UC_ARM_REG_R5)==r[1]
            self.write32(r[1],0x12340000)
            self.pop([UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_PC])
            return
        uc.reg_write(UC_ARM_REG_R0,result)
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))

    def pop(self,registers):
        sp=self.uc.reg_read(UC_ARM_REG_SP)
        for i,reg in enumerate(registers): self.uc.reg_write(reg,self.read32(sp+4*i))
        self.uc.reg_write(UC_ARM_REG_SP,sp+4*len(registers))

    def call(self,name,*args):
        regs=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
        for reg,value in zip(regs,args): self.uc.reg_write(reg,value)
        saved=[UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
               UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11]
        for i,reg in enumerate(saved): self.uc.reg_write(reg,0x11220000+i)
        self.uc.reg_write(UC_ARM_REG_SP,STACK)
        self.uc.reg_write(UC_ARM_REG_LR,STOP|1)
        self.stopped=False
        start=self.symbols[name] if isinstance(name,str) else name|1
        self.uc.emu_start(start,0,count=100000)
        assert self.stopped and self.uc.reg_read(UC_ARM_REG_SP)==STACK
        assert [self.uc.reg_read(r) for r in saved]==[0x11220000+i for i in range(8)]
        return self.uc.reg_read(UC_ARM_REG_R0)

    def choose(self,control,index):
        self.focused=control
        self.indices[control]=index
        return self.call("highlight_display",0x90014,0xe0f0,0)

    def menu(self, selected, disabled=False, scrolling=False):
        control=RAM+0x72000
        self.uc.mem_write(control+0x96,struct.pack("<H",3))
        for i,reg in enumerate((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)):
            self.uc.reg_write(reg,0x123+i)
        self.uc.reg_write(UC_ARM_REG_R4,control)
        self.uc.reg_write(UC_ARM_REG_R9,3 if selected else 2)
        self.uc.reg_write(UC_ARM_REG_SP,STACK)
        self.uc.reg_write(UC_ARM_REG_LR,STOP|1)
        self.uc.mem_write(STACK,struct.pack("<6I",0x111,0x3011 if disabled else 0x2011,0xffffffff,0x222,24,0x8410))
        self.stopped=False
        self.uc.emu_start(self.symbols["highlight_menu_scroll" if scrolling else "highlight_menu_text"],0,count=100000)
        assert self.stopped and self.uc.reg_read(UC_ARM_REG_SP)==STACK
        assert self.uc.reg_read(UC_ARM_REG_R4)==control and self.uc.reg_read(UC_ARM_REG_R9)==(3 if selected else 2)
        return self.menu_color


def check_native_selectors(image, report):
    """Run actual item cloning, linked lists, selection and title copying.

    Only object lookup and imported kernel allocation/memory services are
    modeled here; the resource-ID title helper is deliberately NOT stubbed.
    """
    native = {0x8806d3d6,0x8806d12c,0x8806d42c,0x8806d36a,
              0x8806d06c,0x8806d0dc}
    p = Phone(image, report, native_services=native)
    u = p.uc
    vtable = RAM+0x74000
    get_type = RAM+0x74100
    u.mem_write(get_type,bytes.fromhex("40f2fc307047")) # movw r0,0x3fc; bx lr
    p.write32(vtable+0x18,get_type|1)
    objects = (RAM+0x71000,RAM+0x71200)
    for obj in objects:
        p.write32(obj,vtable)
        p.write32(obj+0xe0,32) # native selector capacity, normally constructor
    # Execute the genuine ARM veneers before modeling their kernel targets.
    for veneer in (0x88091bf8,0x88091bf0,0x88091c08,0x88091c10,0x88091c18,0x88091c20):
        assert bytes(u.mem_read(veneer,4))==bytes.fromhex("04f01fe5")
        target=p.read32(veneer+4)
        page=target&~0xfff
        if not any(start<=page<=end for start,end,perms in u.mem_regions()):
            u.mem_map(page,0x1000)
        def kernel(uc,addr,size,data,veneer=veneer,target=target):
            assert bool(uc.reg_read(UC_ARM_REG_CPSR)&0x20)==bool(target&1)
            a,b,c=(uc.reg_read(reg) for reg in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2))
            result=a
            if veneer==0x88091bf8:
                result=p.heap
                p.heap=(p.heap+a+7)&~7
            elif veneer in (0x88091c08,0x88091c18):
                uc.mem_write(a,bytes(b))
            elif veneer in (0x88091c10,0x88091c20):
                uc.mem_write(a,bytes(uc.mem_read(b,c)))
            uc.reg_write(UC_ARM_REG_R0,result)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
        u.hook_add(UC_HOOK_CODE,kernel,begin=target&~1,end=target&~1)
    def resource_lookup(uc,addr,size,data):
        resource=uc.reg_read(UC_ARM_REG_R0)
        assert ((resource&~0x40000000)>>16)<0x40, "Native title resource module out of range"
        raise AssertionError("Custom selector title must use native String, not resource lookup")
    u.hook_add(UC_HOOK_CODE,resource_lookup,begin=0x886e8dc4,end=0x886e8dc4)
    assert p.call("highlight_display",0x90014,0xf021,0)==0x55
    for obj,count,caption in zip(objects,(7,4),("Фон выделения","Буквы выделения")):
        assert p.read32(obj+0x108)==count and p.read32(obj+0xe4)==0
        length=struct.unpack("<H",u.mem_read(obj+0xf4,2))[0]
        assert p.text(p.read32(obj+0xf0),length)==caption
        node=p.read32(obj+0x10c)
        labels=[]
        for _ in range(count):
            item=p.read32(node)
            length=struct.unpack("<H",u.mem_read(item+8,2))[0]
            labels.append(p.text(p.read32(item+4),length))
            node=p.read32(node+4)
        assert node==p.read32(obj+0x10c) and len(set(labels))==count
    return True


def check_vm(image):
    # Run the actual kernel scatter decompressor, not an assumed flat RAM map.
    kernel=(ROOT/"backup/l728-kernel-ecc.bin").read_bytes()
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    uc.mem_map(0x809c5000,0xc10000)
    uc.mem_write(0x809c5e00,kernel)
    uc.mem_map(RAM,0x60000)
    uc.mem_map(0x100000,0x1000)
    source,destination,length,decoder=struct.unpack_from("<4I",kernel,0xba4390)
    assert (source,destination,length,decoder)==(0x81591ba0,RAM,0x57504,0x81463738)
    for reg,value in ((UC_ARM_REG_R0,source),(UC_ARM_REG_R1,destination),
                      (UC_ARM_REG_R2,length),(UC_ARM_REG_LR,0x100001)):
        uc.reg_write(reg,value)
    uc.emu_start(decoder|1,0x100000,count=5000000)
    assert uc.reg_read(UC_ARM_REG_PC)==0x100000
    regions=list(struct.iter_unpack("<6I",uc.mem_read(0x817001e0,72)))
    mmi=[r for r in regions if r[0]==BASE]
    assert len(mmi)==1 and mmi[0][1]==0x1000000 and len(image)<=mmi[0][1]


def check_io():
    binary=FOLDER/"highlight-block-io.bin"
    if not binary.exists():
        return False
    code=binary.read_bytes()
    assert len(code)<0x1000
    rejected=[(0,0,0x13d),(0x4c373238,2,0x13d)]
    rejected += [(0x4c373238,1,b) for b in (0,0x143,0x145,0x172,0x17a,0x1c6,0x200)]
    rejected.append((0x4c373238,0,0x1c6))
    for magic,operation,block in rejected:
        uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
        for address,size in ((0x10000,0x2000),(0x20000,0x1000),(0x30000,0x1000)):
            uc.mem_map(address,size)
        uc.mem_write(0x10000,code)
        uc.mem_write(0x11000,struct.pack("<9I",magic,operation,block,0,0,0,0,0,0))
        uc.reg_write(UC_ARM_REG_SP,0x30800)
        uc.reg_write(UC_ARM_REG_LR,0x20000)
        # No MMIO mapped: accessing NAND before rejecting would fail.
        uc.emu_start(0x10200,0x20000,count=10000)
        assert uc.reg_read(UC_ARM_REG_PC)==0x20000
        assert struct.unpack("<I",uc.mem_read(0x11010,4))[0]==1
    return True


def main():
    global FOLDER
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder",type=Path,default=FOLDER)
    args=parser.parse_args()
    FOLDER=args.folder.resolve()
    report=json.loads((FOLDER/"manifest.json").read_text())
    image=(FOLDER/"l728-user-highlight-CANDIDATE.bin").read_bytes()
    source=(ROOT/"experimental/sos-no-flash/l728-user-sos-CANDIDATE.bin").read_bytes()
    assert hashlib.sha256(image).hexdigest()==report["output_sha256"]
    check_vm(image)
    check_native_selectors(image,report)
    io_checked=check_io()
    allowed=set(range(0x30,0x34))|set(range(0x31be64,0x31be68))|set(range(
        report["payload_offset"],report["payload_offset"]+report["payload_bytes"]))
    for hook in report["hooks"]: allowed.update(range(hook["offset"],hook["offset"]+len(bytes.fromhex(hook["replacement"]))))
    padded=source+b"\xff"*(len(image)-len(source))
    assert all(a==b or p in allowed for p,(a,b) in enumerate(zip(image,padded)))
    # Preserve both existing payloads and their hooks byte-for-byte.
    assert image[0x7e13c0:0x7e162c]==source[0x7e13c0:0x7e162c]
    assert image[0x6a2a84:0x6a2a8c]==source[0x6a2a84:0x6a2a8c]
    phone=Phone(image,report)
    out=RAM+0x70000
    assert phone.call(0x881ed5c4,0x4000001f,0x90014,out)==phone.original_image
    assert phone.read32(out)==48
    assert phone.call("highlight_display",0x90014,0xf021,0)==0x55
    assert len(phone.items[0x9fe03])==7 and len(phone.items[0x9fe06])==4
    assert phone.captions[0x9fe02]=="Фон выделения" and phone.captions[0x9fe05]=="Буквы выделения"
    assert phone.call("highlight_string",0x40fe0001,out)==0 or phone.text(phone.read32(out),13)=="Фон выделения"
    assert phone.text(phone.read32(out),13)=="Фон выделения"
    phone.call(0x881ed668,0x40000002,0) # original null-out branch
    phone.call(0x881ed668,0x40000002,out)
    assert phone.read32(out)==0x12340000
    for bg in range(1,7):
        assert phone.choose(0x9fe03,bg)==1
        ptr=phone.call(0x881ed5c4,0x4000001f,0x90014,out)
        assert phone.read32(out)==654
        wrapped=bytes(phone.uc.mem_read(ptr,654))
        assert wrapped[:12]==bytes.fromhex("7361626d0801010000010090")
        bmp=wrapped[12:]
        assert bmp[:2]==b"BM" and struct.unpack_from("<ii",bmp,18)==(1,144)
        color=[0xffe0,0x07e0,0xffff,0xfd20,0xf800,0][bg-1]
        assert bmp[66:]==(struct.pack("<H",color)+b"\0\0")*144
    assert phone.choose(0x9fe03,1)==1
    assert phone.choose(0x9fe06,1)==1
    assert phone.menu(True)==0 and phone.menu(False)==0x8410
    assert phone.menu(True,disabled=True)==0x8410
    assert phone.menu(True,scrolling=True)==0
    for selection in (0,1,2,3):
        assert phone.call(0x88040a0c,selection,0,0)==(0 if selection==1 else 0xef9d)
    assert phone.record==b"L7H\x01\x01\x01\xa5\x5a"
    reboot=Phone(image,report,phone.record)
    assert reboot.call(0x88040a0c,1,0,0)==0
    ptr=reboot.call(0x881ed5c4,0x4000001f,0x90014,out)
    assert struct.unpack("<H",reboot.uc.mem_read(ptr+12+66,2))[0]==0xffe0
    # Native UI registry lookups must ignore our opaque state object.
    assert reboot.call(0x8809d39a,0x9fe0e)==0
    phone.fail_save=True
    assert phone.choose(0x9fe06,2)==1
    assert phone.captions[0x9fe08]=="Не сохранено"
    assert phone.call(0x88040a0c,1,0,0)==0xffff
    phone.fail_save=False
    phone.call("highlight_display",0x90014,0xf022,0)
    assert phone.record[5]==2
    phone.focused=0x901f3
    assert phone.call("highlight_display",0x90014,0xe0f0,0)==0x55
    draw=out+0x100
    phone.uc.mem_write(draw,struct.pack("<8h",0,0,140,35,10,10,100,25))
    phone.call("highlight_preview",draw)
    assert phone.fills and phone.fills[0]==((10,10,100,25),0xffe0)
    assert all(10<=r[0]<=r[2]<=100 and 10<=r[1]<=r[3]<=25 for r,c in phone.fills)
    for bad in (b"bad!\x01\x01\xa5\x5a",b"L7H\x01\xff\x01\x5b\x5a",b"L7H\x01\x01\x01\x00\x5a"):
        fresh=Phone(image,report,bad)
        assert fresh.call(0x88040a0c,1,0,0)==0xef9d
    fresh=Phone(image,report,b"L7H\x01\x01\x01\xa5\x5a")
    fresh.short_read=True
    assert fresh.call(0x88040a0c,1,0,0)==0xef9d
    fresh=Phone(image,report)
    fresh.fail_alloc=True
    assert fresh.call(0x88040a0c,1,0,0)==0xef9d
    assert phone.choose(0x9fe06,0)==1 and phone.menu(True)==0x8410
    print("PASS: kernel VM table (16 MiB); real registry/hooks; list/menu selected text; independent choices; persistence/reboot model; file failures; clipped preview; preserved navigation/SOS bytes")
    print("Widget/filesystem/LCD boundaries modeled; hardware behavior remains to be checked on the phone.")
    (FOLDER/"checks.json").write_text(json.dumps({"output_sha256":report["output_sha256"],
        "focused_execution_passed":True,"mmi_region_bytes":0x1000000,
        "allocator_interworking_checked":True,
        "native_selector_initialization_checked":True,
        "io_rejection_checked":io_checked,
        "modeled_boundaries":["filesystem","widgets","LCD"],"device_tested":False},indent=2)+"\n")


if __name__=="__main__": main()
