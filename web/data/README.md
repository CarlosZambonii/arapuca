# Page data

| File | Where it comes from |
|------|---------------------|
| `live.json` | Regenerated hourly by `.github/workflows/live-map.yml`, which runs `tools/live_export.py` against New Relic. Do not edit by hand: the next run overwrites it. |
| `world-110m.json` | `world-atlas@2.0.2/countries-110m.json`, committed verbatim. |

The world geometry is bundled rather than fetched from a CDN at runtime. It is
the centrepiece of the page, and a map that silently fails to draw because a
third party had a bad minute is worse than 108 KB in the repository. It also
keeps the page working with a strict `connect-src 'self'`.

To refresh it:

```bash
curl -sfL -o web/data/world-110m.json \
  https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json
```

Country shapes are keyed on the ISO 3166-1 numeric code. The honeypot records
the alpha-2 code, and `tools/live_export.py` converts between them with a table
generated once from the `iso-codes` package.
