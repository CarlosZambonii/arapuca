# Bundled libraries

Committed rather than loaded from a CDN. The map is the point of the page, and
a third party having a bad minute should not leave an empty rectangle where the
map was. It also lets the Content Security Policy stay at `script-src 'self'`.

| File | Package | Why |
|------|---------|-----|
| `d3-array.min.js` | `d3-array@3.2.4` | required by d3-geo |
| `d3-geo.min.js` | `d3-geo@3.1.1` | the Natural Earth projection and the path generator |
| `topojson-client.min.js` | `topojson-client@3.1.0` | decodes the world geometry |

Only `d3-geo` is used, not the full `d3` bundle: 60 KB instead of 280 KB. The
colour ramp and the DOM work are eight lines of plain JavaScript rather than
`d3-scale` and `d3-selection`.

To refresh:

```bash
for pkg in d3-array@3.2.4/dist/d3-array d3-geo@3.1.1/dist/d3-geo \
           topojson-client@3.1.0/dist/topojson-client; do
  curl -sfL -o "web/vendor/$(basename ${pkg}).min.js" \
    "https://cdn.jsdelivr.net/npm/${pkg}.min.js"
done
```

Each file is the published minified build, byte for byte, so it can be checked
against the registry.
