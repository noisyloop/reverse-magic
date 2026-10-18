# reverse-magic

Each day this repo looks at a vibe-coded project that is trending, writes up what is actually true about it, and then builds an original app based on the most promising idea. Nothing here is deployed; everything runs on your own machine.

![Latest build: Teardown](2026-10-17/screenshot.png)

| Day | Recon | Build |
|---|---|---|
| [2026-10-17](2026-10-17/) | REA (Reverse Engineer Anything) | [Teardown](2026-10-17/teardown/): drag-and-drop static file analyzer, local only |

## What's in each day's folder

- **Recon notes** (`*-RECON.md`, `RESEARCH.md`): what the trending project is, why it took off, which claims are verified and which are not, plus sources.
- **The build**: a working app with its own README, tests and screenshots.

## Teardown (current build)

Teardown shows you what is inside a file without running it. Drop an executable, archive, document or any other file onto the page and it gives you:

- **Overview**: file type, size, MD5/SHA-1/SHA-256 hashes, and findings with severity and confidence
- **Structure**: headers, sections, imports and entry point for PE (Windows), ELF (Linux), Mach-O (macOS), ZIP/APK/JAR/DOCX, PDF, PNG, JPEG, WASM and Java class files
- **Disassembly**: machine code decoded to assembly for x86-64, x86-32, ARM64, ARM, RISC-V 64 and PowerPC64
- **Strings**: readable text found in the file, searchable
- **Indicators**: URLs, domains, IPs, emails, file paths and registry keys (shown defanged)
- **Entropy**: a chart that highlights packed or encrypted regions
- **Hex**: a raw byte view you can jump into from any other tab

Everything happens in your browser. The file is never uploaded and never executed.

### How to use it

You need [Node.js](https://nodejs.org/) 18 or newer.

```sh
cd 2026-10-17/teardown
npm install
npm run dev          # opens a dev server at http://localhost:5173
```

Then:

1. Open http://localhost:5173 in your browser.
2. Drag a file onto the drop zone, or click it to pick a file (up to 256 MB).
3. Switch between the tabs above. Clicking an offset, string or indicator jumps to that spot in the Hex view; clicking an entry point or code section opens it in Disassembly.
4. Click **Export JSON** to save the full report.
5. Click the logo to clear the file and analyze another.

Other commands:

```sh
npm run build        # production build into dist/
npm test             # parser and disassembler tests
```

To serve a production build, put `dist/` behind any static file server (for example `npx serve dist`). It will not work if opened straight from disk as `file://`, because browsers block Web Workers there.

### Good to know

- Findings are leads, not verdicts. Teardown is not antivirus, and a lack of findings does not mean a file is safe.
- Disassembly is a simple linear sweep from the offset you pick, so data can show up as nonsense instructions. ARM Thumb is not supported.
- Only analyze files you are allowed to examine. Software licenses can forbid reverse engineering even when nothing leaves your machine.

See the [Teardown README](2026-10-17/teardown/README.md) for the full feature list, the safety model, measured accuracy and the project layout.

## License

See [LICENSE](LICENSE).
