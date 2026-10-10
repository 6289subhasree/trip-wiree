Optional fonts. Drop either variable font here and rebuild (`npm run build`):

- `ReferenceSans-Variable.woff2` (weights 100 to 900), used for body text
- `ReferenceDisplay-Variable.woff2` (weights 400 to 900), used for the headline and the score

`app/layout.tsx` writes an `@font-face` rule for each file it finds at build time. Until a file exists the page
uses the system UI font (Segoe UI on Windows) and requests nothing.
