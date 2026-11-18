# redirectchain

**Trace a URL redirect chain hop by hop, and see exactly where the trust breaks.**

A phishing link is never one hop. It is a shortener, then a tracker, then an open redirect on a
site the victim already trusts, then a clone of a login page. Each hop looks innocent alone.
`redirectchain` walks the whole chain, classifies every hop and grades the risk.

<p>
  <img src="https://img.shields.io/badge/python-3.8%2B-0d1117?style=flat-square&logo=python&logoColor=39D353" alt="python" />
  <img src="https://img.shields.io/badge/runtime%20dependencies-zero-0d1117?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/network-opt--in-0d1117?style=flat-square" alt="network optional" />
  <img src="https://img.shields.io/badge/CI%20gate-exit%20codes-0d1117?style=flat-square" alt="ci gate" />
  <img src="https://img.shields.io/badge/license-MIT-0d1117?style=flat-square" alt="MIT" />
</p>

## Why

Users judge a link by the domain in front of them. The chain behind it does the actual work:
`trusted-brand.com` hands the browser to a tracking domain, which hands it to an open redirect,
which lands on a credential form somewhere else entirely. Static URL scanners score the first hop
and miss the payload.

Two modes, both useful:

- **Offline (`--chain`)** for triage of a reported link: paste the hops from your proxy log, a
  sandbox trace or a mail gateway verdict. No network, nothing leaves the box.
- **Live (`--fetch`)** to walk the chain yourself, one hop at a time, redirects disabled so you
  actually see every hop instead of the final answer.

## Install

One file, standard library only.

```bash
git clone https://github.com/mehulpatel23b-pixel/redirectchain.git
cd redirectchain
python3 redirectchain.py --help
```

## Usage

```bash
# classify a single URL statically, no network
python3 redirectchain.py "http://user@bit.ly/3xYz?url=https://evil.example/login"

# walk the chain live, at most 8 hops
python3 redirectchain.py --fetch "https://bit.ly/3xYz" --max-hops 8

# triage a chain exported from your proxy
python3 redirectchain.py --chain examples/chain.json

# pipeline mode
python3 redirectchain.py --fetch "$URL" --json --fail-on medium
```

Chain file formats:

```json
[{"url": "https://bit.ly/x", "status": 301, "location": "https://tracker.example/r?u=https://pay.example/"}]
```

or plain text, one URL per line, optional leading status code:

```text
https://bit.ly/x
302 https://tracker.example/r?u=https://pay.example/
```

Sample output:

```text
chain
----------------------------------------------------------------------------------------------
  [0] 301  https://bit.ly/3xYz
  [1] 302  https://tracker.example/r?u=https://pay.example/login
  [2] 200  https://pay.example/login

SEVERITY RULE                 HOP    DETAIL
----------------------------------------------------------------------------------------------
HIGH     RC-OPEN-REDIRECT     [1]    parameter 'u' redirects off-site to pay.example
MEDIUM   RC-SHORTENER         [0]    bit.ly hides the true destination from the user
MEDIUM   RC-CROSS-DOMAIN      [2]    chain changes registrable domain 2 times
```

## Rules

| Rule | Severity | What it catches |
| :-- | :-- | :-- |
| `RC-SCRIPT-SCHEME` | critical | `javascript:`, `data:` or `vbscript:` as a hop destination |
| `RC-DOWNGRADE` | high | chain drops from https to http mid-flow |
| `RC-USERINFO` | high | `https://brand.com@evil.example` userinfo trick |
| `RC-OPEN-REDIRECT` | high | a query parameter sends the chain to another registrable domain |
| `RC-PLAINTEXT` | medium | hop served over plain http |
| `RC-IP-HOST` | medium | hop host is a bare IP address |
| `RC-PUNYCODE` | medium | `xn--` host that may render as a brand lookalike |
| `RC-SHORTENER` | medium | known URL shortener in the chain |
| `RC-META-REFRESH` | medium | page redirects via `<meta http-equiv=refresh>` |
| `RC-JS-REDIRECT` | medium | page redirects via `location.replace` / `location=` |
| `RC-LOOP` | medium | chain revisits a URL already seen |
| `RC-CROSS-DOMAIN` | low | two or more registrable-domain changes |
| `RC-LONG-CHAIN` | low | more than five hops |
| `RC-ENCODED-PATH` | low | 40+ character base64-looking path segment |
| `RC-REDIRECT-PARAM` | low | redirect parameter constrained to the same site |
| `RC-TRACKING` | info | `utm_*`, `gclid`, `fbclid` and friends |
| `RC-DEAD-END` | info | final hop answers 4xx/5xx |

## Scoring

Each finding carries a weight (critical 40, high 22, medium 11, low 5, info 0), capped at 100.
Grade A is 0-10, B to 25, C to 45, D to 65, E to 85, F above. Any critical or high finding fails
the gate.

## Exit codes

| Code | Meaning |
| :-- | :-- |
| `0` | Nothing at or above `--fail-on` |
| `1` | Threshold breached |
| `2` | No input, or the chain could not be read |

## Design

- **Offline first.** The `--chain` mode never touches the network, so it is safe on a workstation
  or inside a restricted CI runner.
- **Redirects disabled on purpose.** Auto-following hides exactly the hops you are trying to see.
- **Bounded.** Hop cap, per-hop timeout and a 64 KB body read, so a hostile chain cannot stall you.
- **Explainable.** Each finding names the hop index, the reason and the fix.

## Ethics

Use it on links that were reported to you, or on your own infrastructure. It performs a plain GET,
sends no credentials and stores nothing.

## License

MIT. See [LICENSE](LICENSE).
