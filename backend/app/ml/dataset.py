"""Synthetic URL corpus for bootstrapping the classifier.

Trace ships without a third-party dataset, so the first model is trained on URLs
generated from the phishing techniques the rule engine knows about (brand-in-subdomain,
typo/combosquats, IP hosts, abused hosting, @-tricks, ...) and on realistic benign URLs,
including deliberately hard negatives (real login pages, long marketing links) and hard
positives (compromised sites with plain-looking domains).

Metrics on this corpus are optimistic. For real-world accuracy, retrain on labelled data:
    python -m app.ml.train --csv path/to/urls.csv   # columns: url,label (1 = phishing)
"""

from __future__ import annotations

import random
import string

from ..core.indicators import BRANDS, FREE_HOSTING, HIGH_RISK_TLDS, MEDIUM_RISK_TLDS, POPULAR_DOMAINS, URL_SHORTENERS

WORDS = (
    "blue river garden cloud stone maple north harbor bright urban craft pixel summit green "
    "forest coffee kitchen studio market travel daily smart health fitness design media "
    "local family home tech data lab solar ocean silver golden quiet rapid prime nova atlas "
    "orbit spark fresh wild open simple true clear iron cedar willow hill lake valley meadow "
    "bakery books music photo art games sports news science learn code dev build cycle "
    "garden pets coastal mountain desert prairie metro city village island alpine sunset "
    "morning evening lantern compass anchor beacon bridge castle harvest orchard pepper "
    "lemon mint olive berry honey cocoa vanilla tea bean bread pasta pizza taco sushi"
).split()

SLUG_WORDS = (
    "how to make best guide review 2024 2025 new tips ideas easy recipe for beginners vs "
    "top list update release notes announcing our team product launch summer winter sale "
    "learn python react css tutorial introduction advanced performance security cloud"
).split()

LEGIT_TLDS = ["com"] * 14 + ["org"] * 3 + ["net"] * 2 + [
    "io", "co", "edu", "gov", "co.uk", "de", "fr", "ca", "com.au", "in", "nl", "jp", "es", "it", "dev", "ai", "us",
]

PHISH_TLDS_WEIGHTED = (
    sorted(HIGH_RISK_TLDS) * 3 + sorted(MEDIUM_RISK_TLDS) * 2 + ["com"] * 25 + ["net", "org", "info", "co", "us", "ru", "cn", "br", "in"] * 2
)

PHISH_WORDS = (
    "login signin verify verification secure security account update confirm billing "
    "support service customer help alert unlock recovery restore auth session wallet "
    "payment invoice refund claim access online portal webscr id center team"
).split()

LEGIT_SUBDOMAINS = ["www"] * 10 + [""] * 8 + ["blog", "shop", "docs", "support", "mail", "app", "api", "en", "m", "news", "help", "store", "developer", "status"]

PHISH_PATHS = [
    "/{kw}/", "/{brand}/{kw}.php", "/{kw}.php?{param}={hex}", "/wp-includes/{kw}/{brand}/",
    "/{hex}/{kw}.html", "/{kw}/{kw2}/index.html", "/{brand}-{kw}/", "/", "", "/{kw}",
    "/wp-content/plugins/{word}/{brand}/{kw}/", "/{kw}/?email={email}", "/{brand}/{hex}/",
    "/~{word}/{brand}/{kw}.htm", "/{kw}?session={hex}&id={num}", "/{brand}.{kw}/{hex}",
    "/.well-known/{word}/{brand}/{kw}.php", "/{kw}/{brand}/{kw2}/", "/index.php?{param}={brand}",
    "/{kw}-{kw2}/{hex}/", "/admin/{brand}/{kw}", "/{word}/{kw}", "/{hex}",
]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/products/{slug}", "/blog/{year}/{month}/{slug}",
    "/{slug}-{num}", "/search?q={word}", "/watch?v={id11}", "/r/{word}/comments/{id6}/{slug}/",
    "/en-us/{word}/{word2}", "/wiki/{Title}", "/p/{num}", "/questions/{num}/{slug}",
    "/user/{word}", "/docs/{word}/{word2}.html", "/index.php?title={Title}",
    "/category/{word}?page={small}", "/{word}/{word2}?utm_source={word}&utm_medium=email&utm_campaign={word2}_{year}",
    "/news/{year}/{month}/{slug}.html", "/shop/{word}/{slug}?color={word2}&size=m",
    "/careers/{num}", "/help/articles/{num}-{slug}", "/{word}", "/{word}/", "/static/js/main.{hex8}.js",
    "/images/{word}-{num}.jpg", "/api/v2/{word}/{num}", "/events/{slug}", "/login", "/account",
    "/settings/profile", "/download/{word}-{small}.{small}.zip", "/@{word}", "/{word}/{num}/{slug}",
]

HARD_NEGATIVES = [
    "https://accounts.google.com/signin/v2/identifier?service=mail&passive=true&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={hex}&response_type=code&scope=openid",
    "https://www.paypal.com/signin?returnUri=https%3A%2F%2Fwww.paypal.com%2Fmyaccount%2Fsummary",
    "https://appleid.apple.com/sign-in",
    "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F",
    "https://secure.chase.com/web/auth/dashboard#/dashboard/overview",
    "https://www.facebook.com/login/?next=https%3A%2F%2Fwww.facebook.com%2F",
    "https://github.com/login?return_to=%2F{word}%2F{word2}",
    "https://www.linkedin.com/checkpoint/lg/login-submit",
    "https://connect.secure.wellsfargo.com/auth/login/present?origin=cob",
    "https://www.netflix.com/login",
    "https://myaccount.google.com/security-checkup",
    "https://www.dropbox.com/login",
    "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn&ru=https%3A%2F%2Fwww.ebay.com%2F",
    "https://account.microsoft.com/billing/payments",
    "https://www.coinbase.com/signin",
    "https://{word}{word2}.github.io/{word}/",
    "https://{word}-{word2}.netlify.app/",
    "https://docs.google.com/document/d/{hex}{hex8}/edit",
    "https://{word}.wordpress.com/{year}/{month}/{slug}/",
]


def _rand_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choices("0123456789abcdef", k=n))


def _rand_alnum(rng: random.Random, n: int) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=n))


def _fill(template: str, rng: random.Random, brand: str = "") -> str:
    slug = "-".join(rng.sample(SLUG_WORDS, rng.randint(2, 6)))
    vals = {
        "slug": slug,
        "year": str(rng.randint(2012, 2026)),
        "month": f"{rng.randint(1, 12):02d}",
        "num": str(rng.randint(10, 9_999_999)),
        "small": str(rng.randint(1, 20)),
        "word": rng.choice(WORDS),
        "word2": rng.choice(WORDS),
        "Title": rng.choice(WORDS).capitalize() + "_" + rng.choice(WORDS).capitalize(),
        "id11": "".join(rng.choices(string.ascii_letters + string.digits + "-_", k=11)),
        "id6": _rand_alnum(rng, 6),
        "hex": _rand_hex(rng, rng.randint(12, 40)),
        "hex8": _rand_hex(rng, 8),
        "kw": rng.choice(PHISH_WORDS),
        "kw2": rng.choice(PHISH_WORDS),
        "brand": brand or rng.choice(list(BRANDS)),
        "param": rng.choice(["id", "token", "cmd", "session", "ref", "u", "auth", "dispatch"]),
        "email": rng.choice(WORDS) + "%40" + rng.choice(["gmail.com", "outlook.com", "company.com"]),
    }
    out = template
    for key, val in vals.items():
        out = out.replace("{" + key + "}", val)
    return out


def _typo(brand: str, rng: random.Random) -> str:
    homo = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}
    b = list(brand)
    op = rng.choice(["homoglyph", "swap", "drop", "double", "insert"])
    i = rng.randrange(len(b))
    if op == "homoglyph":
        idx = [k for k, ch in enumerate(b) if ch in homo]
        if idx:
            k = rng.choice(idx)
            b[k] = homo[b[k]]
    elif op == "swap" and len(b) > 2:
        i = min(i, len(b) - 2)
        b[i], b[i + 1] = b[i + 1], b[i]
    elif op == "drop" and len(b) > 4:
        del b[i]
    elif op == "double":
        b.insert(i, b[i])
    else:
        b.insert(i, rng.choice(string.ascii_lowercase))
    return "".join(b)


def _brandable_domain(rng: random.Random) -> str:
    style = rng.random()
    if style < 0.45:
        name = rng.choice(WORDS) + rng.choice(WORDS)
    elif style < 0.65:
        name = rng.choice(WORDS) + "-" + rng.choice(WORDS)
    elif style < 0.8:
        name = rng.choice(WORDS) + rng.choice(["hq", "ly", "ify", "co", "app", "labs", "io", "now"])
    else:
        name = rng.choice(WORDS) + rng.choice(WORDS) + str(rng.randint(1, 99)) if rng.random() < 0.3 else rng.choice(WORDS)
    return f"{name}.{rng.choice(LEGIT_TLDS)}"


def legit_url(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.08:
        return _fill(rng.choice(HARD_NEGATIVES), rng)
    if r < 0.12:
        return f"https://{rng.choice(sorted(URL_SHORTENERS))}/{_rand_alnum(rng, rng.randint(5, 8))}"
    if r < 0.5:
        domain = rng.choice(sorted(POPULAR_DOMAINS))
    else:
        domain = _brandable_domain(rng)
    sub = rng.choice(LEGIT_SUBDOMAINS)
    host = f"{sub}.{domain}" if sub else domain
    scheme = "https" if rng.random() < 0.9 else "http"
    return f"{scheme}://{host}{_fill(rng.choice(LEGIT_PATHS), rng)}"


def phishing_url(rng: random.Random) -> str:
    brand = rng.choice(list(BRANDS))
    official = BRANDS[brand][0]
    tld = rng.choice(PHISH_TLDS_WEIGHTED)
    kw = rng.choice(PHISH_WORDS)
    path = _fill(rng.choice(PHISH_PATHS), rng, brand)
    technique = rng.random()

    if technique < 0.13:  # brand in subdomain of an attacker domain
        evil = rng.choice([f"{kw}-{_rand_alnum(rng, 5)}", rng.choice(WORDS) + rng.choice(PHISH_WORDS), _rand_alnum(rng, rng.randint(6, 12))])
        host = rng.choice([f"{official}.{evil}.{tld}", f"{brand}.{evil}.{tld}", f"www.{brand}-{kw}.{evil}.{tld}", f"{brand}.{official}-{kw}.{tld}"])
    elif technique < 0.26:  # combosquat registered domain
        host = rng.choice([f"{brand}-{kw}.{tld}", f"{kw}-{brand}.{tld}", f"{brand}{kw}.{tld}", f"{brand}-{kw}-{rng.choice(PHISH_WORDS)}.{tld}", f"{kw}{brand}{rng.randint(1, 999)}.{tld}"])
        if rng.random() < 0.3:
            host = "www." + host
    elif technique < 0.37:  # typosquat
        host = f"{_typo(brand, rng)}.{rng.choice(['com'] * 4 + [tld])}"
        if rng.random() < 0.4:
            host = rng.choice(["www.", "login.", "secure.", "account."]) + host
    elif technique < 0.44:  # raw IP host
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        port = rng.choice(["", "", ":8080", ":8443", ":2083"])
        host = ip + port
    elif technique < 0.55:  # abused free-hosting platform
        platform = rng.choice([p for p in FREE_HOSTING if "." in p])
        label = rng.choice([f"{brand}-{kw}", f"{kw}-{brand}-{_rand_alnum(rng, 4)}", f"{brand}{kw}", _rand_alnum(rng, 10), f"{kw}-{rng.choice(PHISH_WORDS)}"])
        host = f"{label}.{platform}" if platform not in ("sites.google.com", "storage.googleapis.com", "s3.amazonaws.com", "ipfs.io", "forms.gle") else platform
        if platform == "sites.google.com":
            path = f"/view/{brand}-{kw}/{rng.choice(PHISH_WORDS)}"
        elif platform in ("storage.googleapis.com", "s3.amazonaws.com"):
            path = f"/{_rand_alnum(rng, 10)}/{brand}-{kw}.html"
        elif platform == "ipfs.io":
            path = f"/ipfs/Qm{_rand_alnum(rng, 44)}/{kw}.html"
    elif technique < 0.67:  # compromised/innocuous domain with a deep phishing path
        host = rng.choice(["", "www."]) + _brandable_domain(rng)
        path = _fill(rng.choice(["/wp-content/plugins/{word}/{brand}/{kw}/", "/wp-includes/{kw}/{brand}/index.php", "/{word}/{brand}/{kw}.php", "/.well-known/{word}/{brand}/{kw}.php", "/{hex}/{brand}/{kw}/", "/images/{hex}/{kw}.html", "/{brand}/{kw}/?{param}={hex}"]), rng, brand)
    elif technique < 0.73:  # userinfo @ trick
        evil = f"{_rand_alnum(rng, 8)}.{tld}" if rng.random() < 0.5 else ".".join(str(rng.randint(1, 254)) for _ in range(4))
        host = f"{rng.choice([official, 'www.' + official, brand + '-' + kw])}@{evil}"
    elif technique < 0.77:  # punycode / IDN homograph
        host = f"xn--{_rand_alnum(rng, rng.randint(6, 12))}-{_rand_alnum(rng, 3)}.{rng.choice(['com', tld])}"
    elif technique < 0.85:  # DGA-ish random domains on cheap TLDs
        host = f"{_rand_alnum(rng, rng.randint(8, 18))}.{rng.choice(sorted(HIGH_RISK_TLDS))}"
        if rng.random() < 0.4:
            host = f"{_rand_hex(rng, rng.randint(6, 20))}.{host}"
    elif technique < 0.89:  # http(s) token in host
        host = f"{rng.choice(['https-', 'http-', 'https', 'www-https-'])}{brand}-{kw}.{tld}"
    elif technique < 0.93:  # many-level subdomain chains
        host = ".".join([rng.choice(PHISH_WORDS) for _ in range(rng.randint(3, 5))] + [_rand_alnum(rng, 7), tld])
    elif technique < 0.96:  # shortener (ambiguous on its own)
        host = rng.choice(sorted(URL_SHORTENERS))
        path = "/" + _rand_alnum(rng, rng.randint(5, 8))
    else:  # generic lookalike without brand
        host = f"{rng.choice(PHISH_WORDS)}-{rng.choice(PHISH_WORDS)}-{rng.choice(['portal', 'center', 'online', 'web'])}.{tld}"

    scheme = "https" if rng.random() < 0.62 else "http"
    return f"{scheme}://{host}{path}"


def generate(n_per_class: int = 12_000, seed: int = 1337, label_noise: float = 0.02) -> tuple[list[str], list[int]]:
    rng = random.Random(seed)
    urls: list[str] = []
    labels: list[int] = []
    for _ in range(n_per_class):
        urls.append(legit_url(rng))
        labels.append(0)
        urls.append(phishing_url(rng))
        labels.append(1)
    if label_noise:
        for i in range(len(labels)):
            if rng.random() < label_noise:
                labels[i] = 1 - labels[i]
    return urls, labels
