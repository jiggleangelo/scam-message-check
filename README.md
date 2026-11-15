# scam-message-check

Paste a message (SMS, chat, email text, call note; max 8000 characters, longer input is cut and the page says so) and the page shows:

1. a verdict (likely scam / suspicious / no strong signs),
2. the matched categories, each with a plain reason (top 3 reasons, plus any other matches under "Also matched"),
3. a four-line pause-and-verify checklist.

The page is available in English and 中文 (toggle at the top; the choice is not stored). Four clickable made-up examples fill the box. A Clear button empties it.

## How it works

It uses **fixed pattern rules, not AI**. Each rule has a weight; weights combine as `1 - product(1 - weight)`, then a small deterministic keyword adjustment is added (+0.15 if the text contains words like "OTP", "safe account", "guaranteed"; otherwise +0.05 for non-empty text). Score 0.70 or more is "likely scam", 0.35 or more is "suspicious".

The rules were ported from the PauseCheck / pausekin app (classifier, phrase boost, i18n, service) and were written from public scam advisories.

## Privacy

No server, no storage (no cookies, localStorage or IndexedDB), no third-party scripts, fonts, images or analytics, and no network calls at all. The pasted text is never stored, sent or logged. It works under the CSP `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'`.

## Honest limits

- Fixed rules can miss new tricks, and can flag harmless messages. They are not AI.
- "No strong signs" does **not** mean a message is safe. Still pause and verify.
- The voice-clone and screenshot/OCR rules of the original app are **not** ported: there is no audio or image input here.
- General information only, not legal or financial advice.

## Run and fork

Open `index.html` in a browser, or serve the folder with any static server (for example `python3 -m http.server`). To fork, copy the folder; there is no build step and no dependencies. Rules live in `core.js` (`SIGNALS`, `STRINGS`).

## Tests

```
node --test
```

Tests use only `node:test` and `node:assert`; there is no `package.json`.

## License and links

MIT, see `LICENSE`.

- Matching studio app: https://app-pausekin.manykiln.com/
- Source: https://github.com/jiggleangelo/scam-message-check
- Join: https://join.manykiln.com/?from=scam-message-check
- Privacy: https://manykiln.com/privacy

Free and open source (MIT). Runs in your browser; nothing you type leaves this page. Built by AI agents at Manykiln.
