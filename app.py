"""passaudit — Streamlit GUI.
Run:    streamlit run app.py
Deploy: share.streamlit.io (free)
"""
import io
import math

import pandas as pd
import streamlit as st

from passaudit_core import (
    SCORE_COLORS, SCORE_LABELS, AuditResult, GenerateOptions,
    audit, generate_passphrase, generate_password,
    shannon_entropy_bits,
)

# ---------- page setup ----------
st.set_page_config(
    page_title="passaudit",
    page_icon="🔒",
    layout="centered",
    menu_items={"About": "passaudit — local password auditor with HIBP k-anonymity breach check."},
)

# minimal CSS — just enough to clean up Streamlit's defaults
st.markdown("""
<style>
  .block-container { padding-top: 2rem; max-width: 780px; }
  .stTabs [data-baseweb="tab-list"] { gap: 4px; }
  .pw-meter { display: flex; gap: 4px; margin: 4px 0 12px; }
  .pw-seg { flex: 1; height: 8px; border-radius: 4px; background: #e5e7eb; }
  .pw-out {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #f8fafc; padding: 10px 14px; border-radius: 8px;
    border: 1px solid #e5e7eb; word-break: break-all; font-size: 15px;
  }
  .stat-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
</style>
""", unsafe_allow_html=True)


# ---------- header ----------
st.title("🔒 passaudit")
st.caption("Audit password strength · Check breaches via HIBP k-anonymity · Generate strong passwords")

with st.expander("⚠️ Read before typing a real password"):
    st.markdown("""
- All strength math runs **locally in this Python process** — your password is not stored or logged.
- The breach check uses HaveIBeenPwned's **k-anonymity API**: only the first 5 chars of `SHA1(password)` leave the server. HIBP never sees your password or its full hash.
- However, this app is hosted on Streamlit Cloud (or wherever you deployed it). Treat it like any third-party tool: **don't test passwords you actively use for critical accounts.** Test a similar-style variant instead.
- Source code: link your GitHub repo here.
""")


# =========================================================================
# TABS
# =========================================================================
tab_audit, tab_gen, tab_bulk, tab_learn = st.tabs([
    "🔍 Audit", "🎲 Generate", "📊 Bulk audit", "📚 Learn"
])


# -------------------------------------------------------------------------
# TAB 1 — AUDIT
# -------------------------------------------------------------------------
with tab_audit:
    st.subheader("Audit a password")

    pw = st.text_input("Password", type="password",
                       placeholder="Type or paste — kept in memory only",
                       key="audit_pw")

    col_a, col_b = st.columns([1, 3])
    breach = col_a.checkbox("Check HIBP", value=True)
    show   = col_b.checkbox("Show characters")
    if show and pw:
        st.code(pw, language=None)

    if st.button("Audit", type="primary", use_container_width=True, disabled=not pw):
        with st.spinner("Auditing..."):
            r: AuditResult = audit(pw, breach=breach)

        # --- strength meter ---
        score = r.zxcvbn_score
        st.markdown(
            f"#### Strength: "
            f"<span style='color:{SCORE_COLORS[score]};font-weight:600'>{SCORE_LABELS[score]}</span>",
            unsafe_allow_html=True,
        )
        segs = "".join(
            f"<div class='pw-seg' style='background:{SCORE_COLORS[score] if i <= score else \"#e5e7eb\"}'></div>"
            for i in range(5)
        )
        st.markdown(f"<div class='pw-meter'>{segs}</div>", unsafe_allow_html=True)

        # --- core stats ---
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Length", r.password_length)
        c2.metric("Charset", r.charset_size)
        c3.metric("Entropy", f"{r.entropy_bits:.1f} bits")
        c4.metric("Guesses (zxcvbn)", f"{r.zxcvbn_guesses:.1e}")

        # --- crack-time table ---
        st.markdown("##### Estimated time to crack")
        st.caption("Lower attacker rates = your account is protected by good server-side hashing. Higher rates = the password is exposed (leaked hash, offline attack).")
        ct_df = pd.DataFrame(
            [(k, v) for k, v in r.crack_times.items()],
            columns=["Attacker scenario", "Time to crack (avg)"],
        )
        st.dataframe(ct_df, hide_index=True, use_container_width=True)

        # --- charset breakdown ---
        with st.expander("Character set analysis"):
            st.write(f"**Classes used:** {', '.join(r.charset_used) if r.charset_used else 'none'}")
            st.write(f"**Effective charset size:** `{r.charset_size}`")
            st.write(f"**Naive entropy formula:** `length × log₂(charset) = {r.password_length} × log₂({r.charset_size}) = {r.entropy_bits:.2f} bits`")
            st.info("Naive entropy assumes uniformly random characters. Real-world passwords are predictable, so zxcvbn's 'guesses' estimate is more honest — it models dictionaries, keyboard patterns, l33t-speak, and dates.")

        # --- feedback ---
        if r.feedback_warning:
            st.warning(f"⚠️ {r.feedback_warning}")
        for s in r.feedback_suggestions:
            st.info(f"💡 {s}")

        # --- breach result ---
        if breach:
            if r.breach_error:
                st.warning(f"Breach check failed: {r.breach_error}")
            elif r.breach_count and r.breach_count > 0:
                st.error(
                    f"❌ **Found in breaches:** This exact password appears "
                    f"**{r.breach_count:,}** times in HIBP's corpus. Attackers have it. "
                    f"**Do not use it anywhere.**"
                )
            else:
                st.success("✅ Not found in HaveIBeenPwned's breach corpus.")


# -------------------------------------------------------------------------
# TAB 2 — GENERATE
# -------------------------------------------------------------------------
with tab_gen:
    st.subheader("Generate a strong password")
    st.caption("Uses Python's `secrets` module — cryptographically secure, suitable for real use.")

    mode = st.radio("Style", ["Random characters", "Passphrase (Diceware-style)"],
                    horizontal=True, key="gen_mode")

    if mode == "Random characters":
        length = st.slider("Length", min_value=8, max_value=64, value=20, key="gen_len")
        col1, col2 = st.columns(2)
        with col1:
            use_lower   = st.checkbox("Lowercase (a-z)", value=True)
            use_upper   = st.checkbox("Uppercase (A-Z)", value=True)
            use_digits  = st.checkbox("Digits (0-9)",    value=True)
            use_symbols = st.checkbox("Symbols (!@#…)",  value=True)
        with col2:
            exclude_ambig = st.checkbox("Exclude lookalikes (I, l, 1, O, 0, ...)")
            custom_excl   = st.text_input("Custom exclude characters", value="",
                                          help="e.g. characters your target system rejects")
            count = st.number_input("How many to generate", 1, 50, 1)

        if st.button("Generate", type="primary", use_container_width=True, key="gen_btn"):
            try:
                results = [
                    generate_password(GenerateOptions(
                        length=length,
                        use_lower=use_lower, use_upper=use_upper,
                        use_digits=use_digits, use_symbols=use_symbols,
                        exclude_ambiguous=exclude_ambig,
                        custom_excludes=custom_excl,
                    )) for _ in range(int(count))
                ]
            except ValueError as e:
                st.error(str(e))
                results = []

            for p in results:
                st.markdown(f"<div class='pw-out'>{p}</div>", unsafe_allow_html=True)
                ent = shannon_entropy_bits(p)
                st.caption(f"Entropy ≈ **{ent:.1f} bits** · Length {len(p)}")
                st.write("")

            if results:
                st.download_button(
                    "Download as .txt",
                    data="\n".join(results),
                    file_name="passwords.txt",
                    mime="text/plain",
                )

    else:  # passphrase
        words = st.slider("Number of words", 3, 10, 5)
        sep   = st.text_input("Separator", value="-", max_chars=3)
        col1, col2 = st.columns(2)
        cap     = col1.checkbox("Capitalize words", value=True)
        add_num = col2.checkbox("Append 2 digits",  value=True)
        count   = st.number_input("How many", 1, 20, 1, key="pp_count")

        if st.button("Generate passphrase", type="primary",
                     use_container_width=True, key="pp_btn"):
            for _ in range(int(count)):
                p = generate_passphrase(words=words, sep=sep,
                                        capitalize=cap, add_digit=add_num)
                st.markdown(f"<div class='pw-out'>{p}</div>", unsafe_allow_html=True)
                st.caption(f"Entropy ≈ **{words * math.log2(200):.1f} bits** (from this app's ~200-word list)")
                st.write("")
            st.info("ℹ️ For maximum entropy, swap the built-in 200-word list with the full **EFF 7776-word diceware list** (~12.9 bits per word). See README.")


# -------------------------------------------------------------------------
# TAB 3 — BULK AUDIT
# -------------------------------------------------------------------------
with tab_bulk:
    st.subheader("Bulk audit")
    st.caption("Upload a `.txt` file with one password per line. Useful for auditing a team's chosen passwords or testing a wordlist. Maximum 500 lines.")

    f = st.file_uploader("Upload .txt", type=["txt"])
    do_breach = st.checkbox("Check each against HIBP (slower)", value=False, key="bulk_breach")

    if f and st.button("Run bulk audit", type="primary", use_container_width=True):
        lines = io.StringIO(f.getvalue().decode("utf-8", errors="ignore")).read().splitlines()
        lines = [l for l in lines if l.strip()][:500]

        rows = []
        prog = st.progress(0.0)
        for i, line in enumerate(lines):
            r = audit(line, breach=do_breach)
            rows.append({
                "password (masked)": line[:2] + "•" * max(0, len(line) - 4) + line[-2:] if len(line) > 4 else "•" * len(line),
                "length": r.password_length,
                "score": r.zxcvbn_score,
                "rating": SCORE_LABELS[r.zxcvbn_score],
                "entropy_bits": round(r.entropy_bits, 1),
                "breached": r.breach_count if do_breach else None,
            })
            prog.progress((i + 1) / len(lines))

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # quick summary
        weak = df[df["score"] <= 1].shape[0]
        st.markdown(f"**Summary:** {len(df)} passwords audited · "
                    f"**{weak}** rated Weak or Very Weak"
                    + (f" · **{df['breached'].fillna(0).gt(0).sum()}** found in breaches"
                       if do_breach else ""))

        st.download_button(
            "Download report (CSV)",
            data=df.to_csv(index=False),
            file_name="passaudit_report.csv",
            mime="text/csv",
        )


# -------------------------------------------------------------------------
# TAB 4 — LEARN
# -------------------------------------------------------------------------
with tab_learn:
    st.subheader("Why this matters")
    st.markdown("""
**Entropy** measures how unpredictable a password is, in bits. Each bit doubles the work an attacker must do.

| Bits | Random guesses on average | Verdict |
|---|---|---|
| 28 | ~134 million | Cracked in seconds on a laptop |
| 40 | ~550 billion | Hours on a GPU |
| 60 | ~5.7 × 10¹⁷ | Years on serious hardware |
| **80+** | **~6 × 10²³** | Centuries, even for nation-states |

**Formula (naive):** `entropy = length × log₂(charset size)`
A 12-char password from `[a-zA-Z0-9]` (charset 62) → `12 × log₂(62) ≈ 71.5 bits`.

But the formula **lies** when humans pick the chars. `Password123!` has 12 chars from a 72-char set (≈74 bits naive), yet attackers crack it in milliseconds because it's in every dictionary. That's why this app uses **zxcvbn**, which models real attacker behaviour: dictionary matches, l33t substitutions, keyboard patterns, dates, repeats.

**Hashing matters more than you think.** Two passwords with identical entropy can be safe or doomed depending on how the *site* stores them:
- Storing as SHA-256 → attacker tries **10 billion guesses/sec** with a GPU. 60-bit password falls in days.
- Storing as bcrypt/argon2 with proper cost → **10 thousand guesses/sec**. Same 60-bit password lasts millennia.

You can't control how a site hashes your password. So the only defence is **don't reuse passwords**, and **use a password manager** so length doesn't matter to your memory.

**Breach checking via k-anonymity** — HIBP's clever trick: you compute `SHA1(password)`, send only the first 5 hex chars, and receive ~500 candidate suffixes back. You check locally if your full hash is in the response. HIBP never learns your password, not even its full hash. This is the gold standard pattern for privacy-preserving lookup.
""")
    st.divider()
    st.caption("Built with Python · Streamlit · zxcvbn · HaveIBeenPwned k-anonymity API")
