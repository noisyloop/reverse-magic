# REA recon (2026-10-17)

Source: a research pass over the REA repo, its README, press and independent tests. Almost all coverage dates from Oct 7-18, 2026, and star and download numbers move hourly and disagree across sources. Treat everything below as of that window.

## What REA is
- **morluto/rea**, MIT-licensed TypeScript **CLI and MCP server**, created April 14, 2026, published to npm as `rea-agents`.
- It orchestrates existing reverse-engineering tools (Hopper, Ghidra, IDA, JADX and others) for AI coding agents and returns "evidence" records with confidence and limitations. It contains no model and no decompiler of its own.
- Targets include native binaries, Electron/JS, .NET, packages (ZIP/APK/IPA/ASAR/DMG), websites, firmware and packet captures.
- It has **no GUI, no upload flow and no drag-and-drop**. Its README says it does not claim to recover original source or automatically clone an application.

## Why it went viral
Posts from Replit's Amjad Masad (Oct 7) and Matthew Berman on X (Oct 8, reported 3.7M views), GitHub Trending, then a Hacker News front-page thread on Oct 10. Reported stars: ~9.7k on Oct 7, ~155k around Oct 14 (the figure in the source that started this), 268k on Oct 16 and ~310k by Oct 18.

## Verified vs. unverified
- Star count is **unproven either way**. npm downloads rose from 16 (Oct 2) to ~103k (Oct 12) and the fork ratio is high, which points toward real interest, but nobody has published a stargazer audit. Peer-reviewed work (arXiv 2412.13459) found AI/LLM repos are the most common target of fake-star campaigns, so use stars as attention, not quality.
- Showcase demos (rebuilding Paint as a web app in minutes, firmware demos) are self-reported video claims and unverified.
- Independent tests found strong citation accuracy but real gaps: missed entries in a known-source Electron app and very large JSON output. A .NET test found plain Claude matched REA on a tiny app, faster.

## Risks worth knowing
- A **lookalike repo (`rea-tools/rea`)** shipped a Windows .exe that Microsoft Defender flagged as a trojan. The maintainer added an official-sources notice. Official sources are github.com/morluto/rea, rea.tools and npm `rea-agents`.
- Runtime capture runs targets with your permissions and is not a sandbox.
- Legal exposure is mostly EULA anti-reverse-engineering clauses, copyright on recovered code and assets, and trade secrets. No lawsuit against REA itself was reported. Nothing here is legal advice.

## Decision
Do not clone REA or reuse its name (the lookalike malware episode shows the name attracts impersonation). Build the adjacent product that fits a drag-and-drop request: a private, client-side static triage tool. That is **Teardown** ([`teardown/`](../teardown/)).

## Sources
- [REA repo](https://github.com/morluto/rea) and [README](https://github.com/morluto/rea/blob/main/README.md)
- [InfoQ](https://www.infoq.com/news/2026/10/reverse-engineer-anything/)
- [Decrypt](https://decrypt.co/380741/gta-v-iphone-free-photoshop-ai-tool-rea-upending-software)
- [HackerNoon hands-on test](https://hackernoon.com/i-tested-rea-githubs-viral-reverse-engineering-tool-on-a-real-electron-app)
- [The GenAI Magazine analysis](https://thegenaimagazine.com/rea-reverse-engineer-anything-github-what-it-does-legal-line)
- [dev.to: before you npx an MCP server](https://dev.to/gabrielanhaia/before-you-npx-an-mcp-server-8-checks-that-would-have-caught-the-fake-rea-repo-300o)
- [agmazon guide](https://agmazon.com/blog/articles/technology/202610/rea-reverse-engineer-anything-guide-en.html)
- [Fake-stars study, arXiv 2412.13459](https://arxiv.org/abs/2412.13459)
