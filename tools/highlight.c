/* L728 T107 V1.0.10 only. Mutable state belongs to the native RAM registry,
 * never to the demand-paged MMI image. Imported kernel veneers use ARM;
 * native MMI routines use Thumb. */
#include <stdint.h>
#include <stddef.h>
#include "highlight_assets.h"
#define FN(addr, result, ...) ((result (*)(__VA_ARGS__))((addr) | 1u))
#define ARM_FN(addr, result, ...) ((result (*)(__VA_ARGS__))(addr))
#define ROOT_CONTROL 0x901d5u
#define BG_ROW 0x9fe01u
#define BG_LABEL 0x9fe02u
#define BG_SELECT 0x9fe03u
#define FG_ROW 0x9fe04u
#define FG_LABEL 0x9fe05u
#define FG_SELECT 0x9fe06u
#define SAMPLE_ROW 0x9fe07u
#define SAMPLE_LABEL 0x9fe08u
#define SAMPLE_CONTROL 0x9fe09u
#define STATE_ID 0x9fe0eu
#define STATE_TYPE 0x484c3732u
#define STR_BG 0x40fe0001u
#define STR_FG 0x40fe0002u

typedef struct { const uint16_t *text; uint16_t length, reserved; } String;
typedef struct {
    uint32_t type, handle, unused, bg, id, fg, loaded, dirty;
} State;
extern const uint32_t highlight_descriptor[];
extern void *highlight_image_original(uint32_t, uint32_t, uint32_t *);
extern void highlight_string_original(uint32_t, String *);

void __aeabi_memclr8(void *ptr, size_t length) {
    volatile uint8_t *p = ptr;
    while (length--) *p++ = 0;
}

static uint32_t match_state(const State *s, uint32_t unused, uint32_t id) {
    (void)unused;
    return s->type == STATE_TYPE && s->id == id;
}

static State *state(void) {
    return FN(0x88313484, State *, void *, uint32_t, uint32_t, uint32_t, uint32_t)(
        (void *)match_state, 0, STATE_ID, 0, 0);
}

static int valid_record(const uint8_t *record) {
    return record[0] == 'L' && record[1] == '7' && record[2] == 'H' &&
        record[3] == 1 && record[4] < BG_COUNT && record[5] < FG_COUNT &&
        record[6] == (uint8_t)(record[4] ^ record[5] ^ 0xa5) && record[7] == 0x5a;
}

static void load(State *s) {
    /* File services can dispatch events: publish defaults before calling them. */
    s->loaded = 1;
    uint8_t record[8];
    uint32_t count = 0;
    uint32_t file = FN(0x881d2d02, uint32_t, const uint16_t *, uint32_t,
        uint32_t, uint32_t)(highlight_path, 0x31, 0, 0);
    if (file) {
        int result = FN(0x881d36ba, int, uint32_t, void *, uint32_t,
            uint32_t *, uint32_t)(file, record, sizeof(record), &count, 0);
        FN(0x881d366a, int, uint32_t)(file);
        if (!result && count == sizeof(record) && valid_record(record)) {
            s->bg = record[4];
            s->fg = record[5];
        }
    }
}

static int save(State *s) {
    uint8_t record[8] = {'L','7','H',1,(uint8_t)s->bg,(uint8_t)s->fg,
        (uint8_t)(s->bg ^ s->fg ^ 0xa5),0x5a};
    uint32_t count = 0;
    uint32_t file = FN(0x881d2d02, uint32_t, const uint16_t *, uint32_t,
        uint32_t, uint32_t)(highlight_path, 0x52, 0, 0);
    if (!file) return 0;
    int result = FN(0x881d3710, int, uint32_t, const void *, uint32_t,
        uint32_t *, uint32_t)(file, record, sizeof(record), &count, 0);
    int closed = FN(0x881d366a, int, uint32_t)(file);
    if (result || closed || count != sizeof(record)) return 0;
    s->dirty = 0;
    return 1;
}

static State *ensure_state(void) {
    State *s = state();
    if (!s) {
        s = ARM_FN(0x88091b60, State *, uint32_t, uint32_t, const char *, uint32_t)(
            sizeof(State), 0x44444444, "l728-highlight", 1);
        if (!s) return 0;
        for (unsigned i = 0; i < sizeof(State)/sizeof(uint32_t); i++)
            ((uint32_t *)s)[i] = 0;
        s->type = STATE_TYPE;
        s->id = STATE_ID;
        s->handle = FN(0x88313370, uint32_t, void *)(s);
    }
    if (!s->loaded) load(s);
    return s;
}

static String string(const uint16_t *text) {
    uint16_t n = 0;
    while (text[n]) n++;
    String s = {text, n, 0};
    return s;
}

void highlight_string(uint32_t id, String *out) {
    if (out && (id == STR_BG || id == STR_FG)) {
        *out = string(id == STR_BG ? label_bg : label_fg);
        return;
    }
    highlight_string_original(id, out);
}

static void label(uint32_t id, const uint16_t *text, uint32_t redraw) {
    String s = string(text);
    FN(0x883391e8, uint32_t, uint32_t, const String *, uint32_t)(id, &s, redraw);
}

static void selector(uint32_t row, uint32_t caption, uint32_t control,
                     const uint16_t *text, const uint16_t *const *choices,
                     uint32_t n, uint32_t selected, uint32_t title) {
    uint32_t item[15] = {0};
    FN(0x881ebc5a, void, uint32_t, uint32_t)(row, 1);
    label(caption, text, 0);
    FN(0x8806d3d6, uint32_t, uint32_t, uint32_t)(control, n);
    for (uint32_t i = 0; i < n; i++) {
        String s = string(choices[i]);
        item[0] = 1;
        item[1] = (uint32_t)s.text;
        item[2] = s.length;
        FN(0x8806d12c, uint32_t, uint32_t, const void *)(control, item);
    }
    FN(0x8806d42c, uint32_t, uint32_t, uint32_t, uint32_t)(control, 0x20, 1);
    FN(0x8806d36a, uint32_t, uint32_t, uint32_t)(control, selected);
    /* The resource-ID title helper bypasses highlight_string entirely.
     * Give its native text setter an actual String instead of a pseudo ID. */
    (void)title;
    void *object = FN(0x8806d6f8, void *, uint32_t)(control);
    if (object) {
        String caption = string(text);
        FN(0x8806d06c, uint32_t, void *, const String *, uint32_t)(object, &caption, 1);
    }
}

static void status(State *s) {
    label(SAMPLE_LABEL, s && s->dirty ? label_unsaved : label_sample, 1);
}

uint32_t highlight_display(uint32_t window, uint32_t event, void *param) {
    State *s;
    if (event == 0xe0f0 || event == 0xfa04) {
        uint32_t focused = FN(0x881ecd68, uint32_t, uint32_t)(window);
        if (focused == BG_SELECT || focused == FG_SELECT) {
            s = ensure_state();
            uint32_t index = FN(0x8806d398, uint32_t, uint32_t)(focused);
            if (s && index < (focused == BG_SELECT ? BG_COUNT : FG_COUNT)) {
                if (focused == BG_SELECT) s->bg = index;
                else s->fg = index;
                s->dirty = 1;
                save(s);
                status(s);
                FN(0x880a0802, uint32_t, uint32_t, uint32_t, void *, uint32_t)(
                    window, 0xf025, 0, 0);
            }
            return 1;
        }
    }
    if (event == 0xf022) {
        s = state();
        if (s && s->dirty) save(s);
    }
    uint32_t result = FN(0x8831af24, uint32_t, uint32_t, uint32_t, void *)(window, event, param);
    if (event == 0xf021) {
        s = ensure_state();
        selector(BG_ROW, BG_LABEL, BG_SELECT, label_bg, bg_names, BG_COUNT,
            s ? s->bg : 0, STR_BG);
        selector(FG_ROW, FG_LABEL, FG_SELECT, label_fg, fg_names, FG_COUNT,
            s ? s->fg : 0, STR_FG);
        FN(0x881ebc5a, void, uint32_t, uint32_t)(SAMPLE_ROW, 1);
        FN(0x88229b70, uint32_t, uint32_t, uint32_t)(SAMPLE_CONTROL, 36);
        status(s);
    }
    return result;
}

void *highlight_image(uint32_t id, uint32_t window, uint32_t *length) {
    State *s = id == 0x4000001f && length ? ensure_state() : 0;
    if (s && s->bg && s->bg < BG_COUNT) {
        *length = sizeof(bg_images[0]);
        return (void *)bg_images[s->bg - 1];
    }
    return highlight_image_original(id, window, length);
}

uint32_t highlight_font(uint32_t selection, void *item, uint32_t unused) {
    (void)item; (void)unused;
    State *s = selection == 1 ? ensure_state() : 0;
    if (selection == 1 && s && s->fg && s->fg < FG_COUNT)
        return fg_colors[s->fg - 1];
    return FN(0x881e84f0, uint32_t, uint32_t)(
        selection == 2 || selection == 3 ? 11 : selection == 1 ? 10 : 9);
}

/* Menu renderers pass color independently from their resource font. Keep
 * the caller's color unless an explicit selected-text override was chosen. */
uint32_t highlight_menu_color(uint32_t original) {
    State *s = ensure_state();
    return s && s->fg && s->fg < FG_COUNT ? fg_colors[s->fg - 1] : original;
}

typedef struct { int16_t x0, y0, x1, y1; } Rect;
typedef struct { Rect area, clip; } Draw;
/* clang's ARM EABI helper for copies from halfword-aligned rectangle data. */
uint32_t __aeabi_uread4(const void *ptr) {
    const uint8_t *p = ptr;
    return p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint32_t packed(int16_t x, int16_t y) {
    return (uint16_t)x | ((uint32_t)(uint16_t)y << 16);
}
static void fill(uint32_t target, const Rect *clip, Rect r, uint32_t color) {
    if (r.x0 < clip->x0) r.x0 = clip->x0;
    if (r.y0 < clip->y0) r.y0 = clip->y0;
    if (r.x1 > clip->x1) r.x1 = clip->x1;
    if (r.y1 > clip->y1) r.y1 = clip->y1;
    if (r.x0 <= r.x1 && r.y0 <= r.y1)
        FN(0x88354260, void, uint32_t, uint32_t, uint32_t, uint32_t)(target,
            packed(r.x0,r.y0), packed(r.x1,r.y1), color);
}

/* A small high-contrast sample "АБВ 123", using rectangles in the native
 * clipped drawing context; it does not depend on a resource font's colors. */
void highlight_preview(const Draw *draw) {
    static const uint8_t glyphs[7][7] = {
        {14,17,17,31,17,17,17}, {31,16,16,30,17,17,30},
        {30,17,17,30,17,17,30}, {0,0,0,0,0,0,0},
        {4,12,4,4,4,4,14}, {14,17,1,2,4,8,31},
        {30,1,1,14,1,1,30}
    };
    if (!draw) return;
    State *s = state();
    uint32_t bg = s && s->bg < BG_COUNT ? bg_colors[s->bg] : bg_colors[0];
    uint32_t fg = s && s->fg && s->fg < FG_COUNT ? fg_colors[s->fg-1] : 0xef9d;
    uint32_t target = FN(0x881e85de, uint32_t, void)();
    fill(target, &draw->clip, draw->area, bg);
    for (unsigned g=0; g<7; g++) for (unsigned y=0; y<7; y++)
        for (unsigned x=0; x<5; x++) if (glyphs[g][y] & (16u >> x)) {
            int16_t px=draw->area.x0+4+g*18+x*3, py=draw->area.y0+4+y*3;
            Rect r={px,py,px+2,py+2};
            fill(target,&draw->clip,r,fg);
        }
}
