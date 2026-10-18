# Daily recon: 2026-10-17

All traction numbers below are self-reported or from third-party aggregators and were not independently verified. Scores are my own judgment (1-10), not a measured metric.

## Candidates

| Project | What it is | Traction (as reported) | Value | Virality | Buildable in a day | Total |
|---|---|---|---|---|---|---|
| **GeoSports** | Daily 5-question sports trivia where you tap a map | ~1M users in under a month; ~700k MAU; ~$40k/mo (ads + subs) | 8 | 9 | 9 | **26** |
| Taipei Rush ("Taipei GTA") | Free browser open-world driving game | 1.2M players in 3 days; ~$10k in AI tokens | 5 | 10 | 3 | 18 |
| Agent tooling (Orca, ECC, Skills) | Dev tools for coding agents | 96k-295k GitHub stars per vibetrend.dev | 6 | 7 | 5 | 18 |
| Career Ops | One link in, job-fit breakdown, resume, tracker out | Peerlist listing, metric unlabeled | 6 | 4 | 8 | 18 |
| ArtCraft / Photocraft | Open-source Adobe-style desktop apps in Rust | Press coverage, no star counts given; author calls it early alpha | 7 | 6 | 2 | 15 |

## Winner: GeoSports

Why it wins: it has the best mix of proven demand and a simple, copyable loop. One short session per day, a shareable result, no onboarding, and it runs in the browser.

### Growth signals
- Built as a weekend prototype by a non-engineer with Claude, then shared with ~100 friends and an Instagram story (Sportico).
- A newsletter plug and X buzz followed; peak ~150k daily players in week one, ~95k weekday average (Sportico).
- Results are formatted for pasting into group chats. Stork.ai reports a 53% organic share rate and says group chats are the main channel.
- Pro tier: $5/month or $40/year for extra plays; ~1,000 members and ~$47k ARR two weeks in (Sportico). Stork.ai later reports ~1,800 subscribers and most revenue from programmatic ads.

### Stack recon (from Stork.ai, a sponsored-content site, so treat as unverified)
- Coding partner: Claude
- Hosting: Vercel
- Map: MapLibre
- Daily questions: Google Sheets, written by guest "hosts"
- Leaderboards: Upstash Redis
- Payments: Stripe

Discrepancy worth knowing: Sportico says a two-day prototype; Stork.ai headlines "8 hours" but describes a weekend.

## What we built

This pass's first draft (a daily music-geography game) was dropped when the direction changed. The day's build is [Teardown](teardown/); see `REA-RECON.md`.

## Sources
- [vibetrend.dev](https://vibetrend.dev/)
- [Peerlist vibe coding launchpad](https://peerlist.io/launchpad/category/vibe_coding)
- [Sportico: GeoSports went from vibe code to viral](https://www.sportico.com/business/tech/2026/geosports-trivia-game-creator-viral-wordle-1234901573/)
- [Stork.ai: GeoSports build breakdown](https://www.stork.ai/blog/ai-built-this-40kmonth-game-in-8-hours)
- [Startup Fortune: Taipei Rush](https://startupfortune.com/a-solo-coder-spent-10000-in-ai-tokens-to-build-a-gta-clone-of-taipei/)
- [Gizmodo: ArtCraft](https://gizmodo.com/someone-vibe-coded-a-free-knockoff-of-adobe-creative-suite-2000823322)
- [Mad Robot: vibe-coded apps roundup](https://madrobot.blog/guides/vibe-coded/)
