# Fossroot icon

Original artwork: the PKI chain of trust drawn as a root system — a gold
root-CA anchor node branching downward into intermediate-CA nodes, on a navy
tile. `fossroot.svg` is the single source of truth; everything else is
generated from it.

## Files

| File | Used by |
|---|---|
| `fossroot.svg` | master artwork, scalable icon for Linux (`hicolor/scalable`) |
| `fossroot-{16..512}.png` | hicolor icon theme sizes, AppImage/desktop icons |
| `fossroot-256.png` | embedded as the GUI window icon (`gui.rs`) |
| `fossroot.ico` | embedded into the Windows exe (`build.rs` / winresource) |
| `render.html` | rasterization wrapper for headless Chrome |

## Regenerating

Rasterize the master 512 px PNG with headless Chrome (a **fresh** profile per
run — Chrome restores remembered window geometry over `--window-size`
otherwise), then downscale with Pillow, which also packs the `.ico`:

```bash
chrome --headless --disable-gpu --no-first-run --no-default-browser-check \
  --hide-scrollbars --user-data-dir="$(mktemp -d)" \
  --default-background-color=00000000 --window-size=512,512 \
  --screenshot=fossroot-512.png render.html
```

```python
from PIL import Image
src = Image.open("fossroot-512.png").convert("RGBA")
for s in (16, 24, 32, 48, 64, 128, 256):
    src.resize((s, s), Image.LANCZOS).save(f"fossroot-{s}.png")
src.save("fossroot.ico", sizes=[(256, 256), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)])
```
