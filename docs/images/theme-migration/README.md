# Theme migration screenshots (issue #280)

Before/after captures for the switch from `jekyll-theme-minimal` to
`just-the-docs` (`remote_theme` @ v0.12.0).

| Folder | Source |
|--------|--------|
| `before/` | Live https://trustprune.com (minimal theme), desktop 1280×900 and mobile 390×844 |
| `after-light/` | Local Jekyll build with `color_scheme: light` |
| `after-dark/` | Local Jekyll build with `color_scheme: dark` (config-only; no visitor toggle) |

Code-block pages: allowlists, usage, home/index. Blog post captured in after-light.

URL check: `docs/check-urls.sh` against `_site` (or `BASE_URL=…` against a live host).
