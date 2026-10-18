# Brand assets

Exported from the SM monogram pack (VectorCraft). Re-export from the master
file rather than editing a PNG.

- `logo-primary.svg` and `logo-reversed.svg`: original vector exports.
- `icon-light-*`: opaque white brand tiles used by the README and landing
  page. These stay readable on any background without GitHub theme detection.
- `icon-dark-*`, `icon-maskable-512.png`: app/web manifest variants.
- `og-card-1200x630.png`: Open Graph and Twitter card image.
- `macapp/AppIcon-1024.png` (repository root) is the dark monogram used to build
  the macOS `AppIcon.icns` in `scripts/build-mac-app.sh`.

Product screenshots in `docs/assets/sm-secrets*.png` and `sm-import*.png` are
captured from the current app using `python3 scripts/capture-docs.py`. The
fixture uses only dummy values and never touches the real vault or Keychain.
