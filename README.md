# 🔒 passaudit

A Streamlit web app to audit password strength, check breach exposure (via HIBP k-anonymity), and generate cryptographically-secure passwords.

## Features

- **Audit** — entropy math, zxcvbn attacker-aware scoring, crack-time estimates against 5 attacker profiles (online throttled → nation-state)
- **Generate** — random characters or Diceware-style passphrase, using Python `secrets` (CSPRNG)
- **Bulk audit** — upload a `.txt`, get a CSV report. Caps at 500 lines.
- **Learn** — built-in explanation of entropy, hashing, and k-anonymity

## Run locally

```bash
git clone <your-repo>
cd passaudit
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Opens at `http://localhost:8501`.

## Deploy free

1. Push this folder to a public GitHub repo.
2. Go to https://share.streamlit.io → **New app** → pick repo → main file = `app.py`.
3. Done. You get a `*.streamlit.app` URL.

Alternative free hosts: Hugging Face Spaces, Render, Railway.

## Security notes

- Strength math and password generation run **locally** in the Python process. Passwords are not written to disk or logged.
- The breach check sends only `SHA1(password)[:5]` to the HIBP `/range` API. This is the [k-anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords) — HIBP never sees your password or its full hash.
- However, since this app is hosted, treat the input box like any third-party tool: prefer to test password *patterns* and *variants*, not your live credentials. The HIBP request leaves the server.
- The included Diceware word list is short (~200 words). For real use, replace `WORDS` in `passaudit_core.py` with the [full EFF long list](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt) (7776 words, 12.92 bits per word).

## Project structure

```
passaudit/
├── app.py              # Streamlit UI
├── passaudit_core.py   # auditing + generation logic (UI-agnostic)
├── requirements.txt
└── README.md
```

## License

MIT.
