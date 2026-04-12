"""
Search Agent Sanitizer v3 — OCR-first, maximum accuracy.

Pipeline (strict order):
  1. OCR SANITIZE  — Render text to image, OCR back. Ground truth extraction.
  2. REGEX DETECT  — Pattern match on clean OCR output.
  3. REGEX REDACT  — Strip detected injection patterns.
  4. URL/EMAIL REDACT — Strip exfiltration channels.
  5. TRUST WRAP    — Tag content as HOSTILE or UNTRUSTED.

OCR renders at 300 DPI, 20pt DejaVu Sans Mono, 2400px width, TIFF format,
LSTM engine (--oem 1). Cap height lands at ~30px — the documented sweet
spot for Tesseract LSTM accuracy.

Red team validated: 12/12 attacks neutralized (2026-04-12).
"""

import logging
import os
import re
import subprocess
import tempfile

log = logging.getLogger("sanitize")


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 1: OCR Sanitization (ground truth — runs FIRST)
#
# Since we GENERATE the image, we control every variable:
#   - Font: DejaVu Sans Mono (monospace, no ligatures, max OCR accuracy)
#   - DPI: 300 (Tesseract minimum for reliable results)
#   - Pointsize: 20pt at 300dpi → cap height ~30px (optimal 20-40px range)
#   - Width: 2400px (~100 chars/line, minimizes wrapping artifacts)
#   - Format: TIFF (lossless, no alpha channel issues)
#   - Contrast: pure black (#000) on pure white (#FFF)
#   - Border: 10px white padding (helps Tesseract edge detection)
#   - Engine: LSTM only (--oem 1, 5-15% better than legacy)
# ═══════════════════════════════════════════════════════════════════════════

def _check_ocr_prerequisites():
    """Verify ImageMagick and Tesseract are available."""
    for cmd, name in [('convert', 'ImageMagick'), ('tesseract', 'Tesseract')]:
        try:
            subprocess.run(
                [cmd, '--version'],
                capture_output=True, timeout=5, check=False,
            )
        except FileNotFoundError:
            raise RuntimeError(f"OCR prerequisite missing: {name} ({cmd})")


_ocr_checked = False


def ocr_sanitize(text: str, chunk_size: int = 6000) -> tuple[str, bool]:
    """
    Render text to image via ImageMagick, OCR back via Tesseract.

    Returns (sanitized_text, success_bool).
    Chunk size reduced from 8000 to 6000 to account for larger font.
    """
    global _ocr_checked
    if not _ocr_checked:
        _check_ocr_prerequisites()
        _ocr_checked = True

    if not text or not text.strip():
        return "", True

    if len(text) > chunk_size:
        chunks = []
        all_ok = True
        for i in range(0, len(text), chunk_size):
            chunk = text[i:i + chunk_size]
            result, ok = _ocr_single(chunk)
            if result:
                chunks.append(result)
            if not ok:
                all_ok = False
        return '\n'.join(chunks), all_ok
    else:
        return _ocr_single(text)


def _ocr_single(text: str) -> tuple[str, bool]:
    """OCR a single chunk with maximum accuracy settings."""
    tmp_dir = tempfile.mkdtemp(prefix="search-ocr-")
    txt_path = os.path.join(tmp_dir, "input.txt")
    img_path = os.path.join(tmp_dir, "render.tif")

    try:
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(text)

        # ── ImageMagick: render text to high-quality image ──────────
        #
        # -density 300       → 300 DPI (Tesseract minimum for accuracy)
        # -size 2400x        → wide canvas, ~100 chars/line at 20pt
        # -font DejaVu-Sans-Mono → monospace, no ligatures, known to Tesseract
        # -pointsize 20      → at 300dpi gives cap height ~30px (optimal range)
        # -background white  → clean white background
        # -fill black        → pure black text (maximum contrast)
        # caption:@file      → read from file, handles multiline
        # -alpha remove      → strip any transparency
        # -bordercolor White → padding color
        # -border 10x10      → 10px border padding (Tesseract edge detection)
        # -sharpen 0x1       → crisp text edges
        # -depth 8           → 8-bit depth (no unnecessary color depth)
        # -type Grayscale    → force grayscale (Tesseract preference)
        # -compress None     → no compression (lossless TIFF)

        render = subprocess.run([
            'convert',
            '-density', '300',
            '-size', '2400x',
            '-font', 'DejaVu-Sans-Mono',
            '-pointsize', '20',
            '-background', 'white',
            '-fill', 'black',
            'caption:@' + txt_path,
            '-alpha', 'remove',
            '-bordercolor', 'White',
            '-border', '10x10',
            '-sharpen', '0x1',
            '-depth', '8',
            '-type', 'Grayscale',
            '-compress', 'None',
            img_path,
        ], capture_output=True, text=True, timeout=60)

        if render.returncode != 0:
            log.warning(f"ImageMagick failed: {render.stderr[:300]}")
            return _fallback_strip(text), False

        if not os.path.exists(img_path):
            log.warning("ImageMagick produced no output image")
            return _fallback_strip(text), False

        # ── Tesseract: OCR the image with optimal settings ─────────
        #
        # --oem 1     → LSTM engine only (5-15% better accuracy)
        # --psm 6     → single uniform block of text
        # --dpi 300   → confirm DPI to Tesseract
        # -l eng      → English language model
        # -c preserve_interword_spaces=1 → keep spacing accurate

        ocr = subprocess.run([
            'tesseract', img_path, 'stdout',
            '--oem', '1',
            '--psm', '6',
            '--dpi', '300',
            '-l', 'eng',
            '-c', 'preserve_interword_spaces=1',
        ], capture_output=True, text=True, timeout=60)

        if ocr.returncode != 0:
            log.warning(f"Tesseract failed: {ocr.stderr[:300]}")
            return _fallback_strip(text), False

        result = ocr.stdout.strip()
        if not result:
            log.warning("Tesseract produced empty output")
            return _fallback_strip(text), False

        return result, True

    finally:
        for p in [txt_path, img_path]:
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass


def _fallback_strip(text: str) -> str:
    """Fallback when OCR fails: strip invisible Unicode characters."""
    cleaned, _ = strip_invisible_unicode(text)
    return cleaned


# Unicode stripping (kept as fallback only — OCR handles this natively)

_INVISIBLE = set(
    '\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064'
    '\ufeff\u00ad\u034f\u061c\u180e'
)
_BIDI = set(
    '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069'
)
_TAG_RANGE = range(0xE0001, 0xE007F + 1)
_VS1 = range(0xFE00, 0xFE0F + 1)
_VS2 = range(0xE0100, 0xE01EF + 1)


def strip_invisible_unicode(text: str) -> tuple[str, int]:
    """Remove invisible/malicious Unicode characters. Fallback for OCR failure."""
    import unicodedata
    removed = 0
    cleaned = []
    for ch in text:
        cp = ord(ch)
        if (ch in _INVISIBLE or ch in _BIDI or
                cp in _TAG_RANGE or cp in _VS1 or cp in _VS2):
            removed += 1
            continue
        if unicodedata.category(ch) == 'Cf' and ch not in ('\n', '\r', '\t'):
            removed += 1
            continue
        cleaned.append(ch)
    return ''.join(cleaned), removed


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 2: Prompt Injection Regex Scanner (runs on OCR output)
# ═══════════════════════════════════════════════════════════════════════════

INJECTION_PATTERNS = [
    # Direct instruction override
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions?", "instr_override"),
    (r"(?i)ignore\s+(all\s+)?above\s+instructions?", "instr_override"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+", "instr_override"),
    (r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+", "instr_override"),

    # Role reassignment
    (r"(?i)you\s+are\s+now\s+", "role_reassign"),
    (r"(?i)act\s+as\s+(a\s+|an\s+)?", "role_reassign"),
    (r"(?i)new\s+role\s*:", "role_reassign"),
    (r"(?i)system\s*:\s*you\s+are", "role_reassign"),
    (r"(?i)from\s+now\s+on\s*,?\s*you", "role_reassign"),

    # System prompt extraction
    (r"(?i)reveal\s+(your\s+)?(system\s+)?prompt", "prompt_extract"),
    (r"(?i)show\s+(me\s+)?(your\s+)?(system\s+)?instructions?", "prompt_extract"),
    (r"(?i)repeat\s+(your\s+)?(system\s+)?prompt", "prompt_extract"),
    (r"(?i)what\s+(are|is)\s+(your\s+)?(system\s+)?instructions?", "prompt_extract"),

    # Data exfiltration via markdown/image
    (r'!\[.*?\]\(https?://[^\s)]+', "md_exf"),
    (r'(?i)<img\s+src\s*=\s*["\x27]https?://', "img_exf"),
    (r"(?i)fetch\s+(this\s+)?url", "url_fetch"),
    (r"(?i)send\s+(this\s+)?data\s+to", "data_exf"),
    (r"(?i)make\s+a\s+(get|post)\s+request\s+to", "req_inj"),

    # Hidden instruction markers
    (r"(?i)IMPORTANT\s*:\s*(?:you\s+must|always|never|do\s+not)", "hidden_instr"),
    (r"(?i)CRITICAL\s*:\s*(?:override|ignore|change)", "hidden_instr"),
    (r"(?i)ADMIN\s*:\s*", "admin_spoof"),
    (r"(?i)\[SYSTEM\]", "sys_spoof"),
    (r"(?i)<\s*system\s*>", "sys_tag_inj"),
    (r"(?i)BEGIN\s+TRUSTED\s+CONTENT", "trust_boundary"),

    # Obfuscated injection
    (r"(?i)ign[o0]re\s+prev[i1]ous", "obfusc_override"),
    (r"(?i)1gnore\s+previous", "obfusc_override"),
    (r"(?i)d[i1]sregard", "obfusc_override"),

    # Delimiter injection
    (r"---+\s*(?:system|assistant|user)\s*---+", "delim_inj"),
    (r"```\s*(?:system|prompt|instructions?)", "fence_inj"),

    # Encoded payloads
    (r"(?i)base64\s*:\s*[A-Za-z0-9+/=]{50,}", "b64_payload"),
    (r"(?i)decode\s+(?:this|the\s+following)\s*:", "decode_instr"),

    # Command execution
    (r'(?i)(?:curl|wget|fetch)\s+(?:(?:-[a-zA-Z]\s+)*)https?://\S+', "cmd_url"),
    (r'(?i)\|\s*(?:ba)?sh\b', "pipe_shell"),
]

_COMPILED_PATTERNS = [(re.compile(p), label) for p, label in INJECTION_PATTERNS]


def scan_for_injections(text: str) -> list[dict]:
    """Scan text for prompt injection patterns."""
    findings = []
    for pattern, label in _COMPILED_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "type": label,
                "match": match.group()[:100],
                "position": match.start(),
            })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 3: Redaction (strip detected patterns + exfil channels)
# ═══════════════════════════════════════════════════════════════════════════

def redact_injections(text: str, findings: list[dict]) -> str:
    """Replace detected injection patterns with [REDACTED] markers."""
    if not findings:
        return text
    redacted = text
    for finding in sorted(findings, key=lambda f: f["position"], reverse=True):
        match_text = finding["match"]
        ftype = finding["type"]
        idx = redacted.find(match_text)
        if idx != -1:
            redacted = (
                redacted[:idx]
                + f"[REDACTED:{ftype}]"
                + redacted[idx + len(match_text):]
            )
    return redacted


ALLOWED_DOMAINS = {
    "github.com", "gitlab.com", "gnu.org", "kernel.org",
    "cve.org", "nvd.nist.gov", "cve.mitre.org",
    "security.archlinux.org", "ubuntu.com", "debian.org",
    "brew.sh", "formulae.brew.sh", "npmjs.com",
    "pypi.org", "crates.io", "wikipedia.org",
    "snyk.io", "opencve.io", "stackoverflow.com",
}


def redact_urls_and_emails(text: str) -> tuple[str, int]:
    """Redact URLs, emails, and IP:port patterns not on the allowlist."""
    count = 0

    def _replace_url(m):
        nonlocal count
        url = m.group(0)
        for domain in ALLOWED_DOMAINS:
            if domain in url:
                return url
        count += 1
        return "[REDACTED:url]"

    def _replace_email(m):
        nonlocal count
        email = m.group(0)
        for domain in ALLOWED_DOMAINS:
            if domain in email:
                return email
        count += 1
        return "[REDACTED:email]"

    def _replace_endpoint(m):
        nonlocal count
        count += 1
        return "[REDACTED:endpoint]"

    redacted = re.sub(r'https?://[^\s<>)\]]+', _replace_url, text)

    redacted = re.sub(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        _replace_email, redacted,
    )

    redacted = re.sub(
        r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/\S*)?',
        _replace_endpoint, redacted,
    )

    return redacted, count


# ═══════════════════════════════════════════════════════════════════════════
# COMBINED PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def full_sanitize(text: str, source_url: str = "unknown") -> dict:
    """
    Full 5-layer sanitization pipeline. OCR runs FIRST.

    Returns dict with sanitized text, findings, and metadata.
    """
    # Layer 1: OCR (ground truth — strips all invisible chars atomically)
    ocr_output, ocr_ok = ocr_sanitize(text)
    if not ocr_ok:
        log.warning(f"OCR failed for {source_url}, fell back to unicode strip")
    ocr_applied = ocr_ok

    # Measure unicode chars that OCR implicitly stripped
    unicode_removed = 0
    if ocr_ok:
        # Count invisible chars in original that OCR would have dropped
        _, unicode_removed = strip_invisible_unicode(text)

    # Layer 2: Regex DETECT (on clean OCR output)
    findings = scan_for_injections(ocr_output)
    if findings:
        log.warning(
            f"Injection patterns in {source_url}: "
            f"{[f['type'] for f in findings]}"
        )

    # Layer 3: Regex REDACT
    redacted = redact_injections(ocr_output, findings)

    # Layer 4: URL/email REDACT
    redacted, urls_redacted = redact_urls_and_emails(redacted)
    if urls_redacted > 0:
        log.info(f"Redacted {urls_redacted} URLs/emails/endpoints from {source_url}")

    sanitized = redacted

    # Layer 5: Trust WRAP
    trust_level = "HOSTILE" if findings else "UNTRUSTED"

    wrapped = (
        f'<UNTRUSTED_WEB_CONTENT source="{source_url}" trust="{trust_level}">\n'
        f"{sanitized}\n"
        f"</UNTRUSTED_WEB_CONTENT>"
    )

    return {
        "sanitized_text": sanitized,
        "wrapped_text": wrapped,
        "injection_findings": findings,
        "unicode_chars_removed": unicode_removed,
        "urls_redacted": urls_redacted,
        "ocr_applied": ocr_applied,
        "source": source_url,
    }
