# BhoomiAI — Real Functional Browser MVP

This is a functional, dependency-light MVP for the SIH land-record digitization problem.

## What actually works
- Role switch: Citizen / Verifier / Admin
- Dashboard with live browser-local metrics
- Image OCR using Tesseract.js
- Gujarati / Hindi / English language selection (language data is downloaded by Tesseract.js on first use)
- PDF page rendering and multi-page OCR using PDF.js
- Field extraction for common labels: owner, survey number, area, village, district
- Prototype confidence estimate
- Validation rules and duplicate survey detection
- Verifier queue and approve/issue actions
- Browser-local record persistence using localStorage
- CSV export
- Prototype GIS map using Leaflet + OpenStreetMap
- Responsive UI

## Run
### Easiest
Open this folder in VS Code and use **Live Server** on `index.html`.

Do NOT double-click the HTML for the PDF workflow; use a local server.

### Alternative
Any static local server works, for example:
`python -m http.server 5500`
Then open `http://localhost:5500`.

## Important limitations
- This MVP stores metadata and OCR results in the browser's localStorage. It is not a production government database.
- Original uploaded files are processed in the browser and are not permanently uploaded to a server.
- Government LRMS/DILRMP APIs are not connected. Authorized access would be required.
- The extraction logic is a prototype parser, not a production ML/NLP model.
- Handwriting recognition and difficult scans can fail; human verification is intentionally part of the workflow.
- Internet is needed on first use because Tesseract.js language/model assets, PDF.js and map tiles are loaded from CDNs.
