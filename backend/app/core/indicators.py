"""Static threat-indicator knowledge: brands, keywords, risky TLDs, shorteners and hosting platforms."""

# Brand name -> registered domains legitimately owned by that brand.
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "microsoftonline.com", "office.com", "windows.net", "azure.com"),
    "office365": ("office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "office.com", "microsoft.com"),
    "onedrive": ("onedrive.com", "live.com", "microsoft.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "google": ("google.com", "gmail.com", "googleusercontent.com", "youtube.com", "goo.gl", "googleapis.com"),
    "gmail": ("gmail.com", "google.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com", "amazon.ca", "amazon.fr"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "dropbox": ("dropbox.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",),
    "chase": ("chase.com", "jpmorganchase.com"),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "citibank": ("citibank.com", "citi.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "barclays": ("barclays.com", "barclays.co.uk"),
    "santander": ("santander.com", "santander.co.uk"),
    "americanexpress": ("americanexpress.com", "aexp.com"),
    "capitalone": ("capitalone.com",),
    "venmo": ("venmo.com",),
    "zelle": ("zellepay.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "royalmail": ("royalmail.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "kraken": ("kraken.com",),
    "blockchain": ("blockchain.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "ebay": ("ebay.com", "ebay.co.uk"),
    "yahoo": ("yahoo.com",),
    "spotify": ("spotify.com",),
    "github": ("github.com", "github.io"),
    "walmart": ("walmart.com",),
    "roblox": ("roblox.com",),
    "discord": ("discord.com", "discord.gg", "discordapp.com"),
    "telegram": ("telegram.org", "t.me"),
    "verizon": ("verizon.com",),
    "irs": ("irs.gov",),
    "hmrc": ("gov.uk",),
    "costco": ("costco.com",),
    "booking": ("booking.com",),
    "airbnb": ("airbnb.com",),
    "steamcommunity": ("steamcommunity.com",),
}

# Brands whose names are common English words / short: only match as whole tokens.
WHOLE_TOKEN_BRANDS = {"apple", "chase", "steam", "booking", "irs", "dhl", "usps", "kraken", "zelle", "venmo", "hsbc"}

SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "validate",
    "account", "update", "secure", "security", "banking", "confirm", "password", "passwd",
    "credential", "wallet", "suspend", "suspended", "unlock", "locked", "billing", "invoice",
    "payment", "webscr", "authenticate", "recover", "recovery", "restore", "alert", "limited",
    "unusual", "reset", "session", "ebayisapi", "bonus", "gift", "prize", "claim", "airdrop",
    "refund", "support", "helpdesk", "customer", "service", "authorize", "activity", "seed",
    "connect-wallet", "mfa", "2fa", "otp", "kyc",
)

# TLDs with disproportionately high abuse rates (Spamhaus / Interisle reports).
HIGH_RISK_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "cfd", "sbs",
    "buzz", "rest", "bond", "click", "monster", "quest", "lol", "gdn", "men", "loan", "work",
    "country", "kim", "date", "faith", "racing", "win", "bid", "stream", "download", "party",
    "review", "science", "cricket", "accountant", "su", "pw", "cam", "surf", "uno", "best",
}
MEDIUM_RISK_TLDS = {
    "online", "site", "website", "space", "live", "shop", "store", "info", "tech", "support",
    "fun", "club", "vip", "cc", "ws", "life", "app", "today", "digital", "link", "pro",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink", "s.id", "t.ly", "v.gd", "qrco.de",
    "short.io", "shorte.st", "adf.ly", "bitly.com", "tinyurl.ws", "u.to", "clck.ru", "x.co",
    "lnkd.in", "ift.tt", "soo.gd", "trib.al", "surl.li", "urlz.fr", "shorturl.asia",
}

# Platforms where anyone can host content under the platform's domain.
FREE_HOSTING = (
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "netlify.app", "vercel.app", "github.io", "glitch.me", "herokuapp.com", "pages.dev",
    "workers.dev", "blogspot.com", "godaddysites.com", "square.site", "ngrok.io",
    "ngrok-free.app", "ngrok.app", "trycloudflare.com", "repl.co", "replit.dev",
    "azurewebsites.net", "web.core.windows.net", "storage.googleapis.com",
    "s3.amazonaws.com", "ipfs.io", "dweb.link", "r2.dev", "webflow.io", "framer.app",
    "framer.website", "carrd.co", "mystrikingly.com", "jimdosite.com", "yolasite.com",
    "surge.sh", "onrender.com", "fly.dev", "notion.site", "sites.google.com",
    "forms.gle", "typedream.app", "wordpress.com", "tilda.ws", "gitbook.io", "zohosites.com",
    "webwave.dev", "myshopify.com", "translate.goog", "ipfs.w3s.link", "nftstorage.link",
)

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "outlook.com",
    "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
    "mail.com", "gmx.com", "gmx.net", "gmx.de", "proton.me", "protonmail.com", "zoho.com",
    "yandex.com", "yandex.ru", "mail.ru", "tutanota.com", "web.de", "qq.com", "163.com",
}

# Well-established registered domains. Used only as a trust signal, never as a hard allow.
POPULAR_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "twitter.com",
    "x.com", "wikipedia.org", "amazon.com", "amazon.co.uk", "amazon.de", "yahoo.com",
    "reddit.com", "linkedin.com", "netflix.com", "microsoft.com", "live.com", "office.com",
    "microsoftonline.com", "bing.com", "apple.com", "icloud.com", "paypal.com", "ebay.com",
    "github.com", "stackoverflow.com", "dropbox.com", "adobe.com", "zoom.us", "slack.com",
    "spotify.com", "twitch.tv", "tiktok.com", "pinterest.com", "tumblr.com", "quora.com",
    "medium.com", "nytimes.com", "bbc.co.uk", "bbc.com", "cnn.com", "theguardian.com",
    "washingtonpost.com", "wsj.com", "bloomberg.com", "reuters.com", "forbes.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
    "capitalone.com", "americanexpress.com", "hsbc.com", "barclays.co.uk", "fedex.com",
    "ups.com", "usps.com", "dhl.com", "walmart.com", "target.com", "bestbuy.com",
    "costco.com", "homedepot.com", "etsy.com", "shopify.com", "booking.com", "airbnb.com",
    "expedia.com", "tripadvisor.com", "uber.com", "lyft.com", "doordash.com", "imdb.com",
    "yelp.com", "salesforce.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com",
    "cloudflare.com", "mozilla.org", "python.org", "npmjs.com", "pypi.org", "docker.com",
    "atlassian.com", "notion.so", "figma.com", "canva.com", "docusign.com", "docusign.net",
    "zoho.com", "mailchimp.com", "hubspot.com", "stripe.com", "squareup.com", "coinbase.com",
    "binance.com", "kraken.com", "steampowered.com", "steamcommunity.com", "roblox.com",
    "discord.com", "telegram.org", "signal.org", "vimeo.com", "dailymotion.com",
    "soundcloud.com", "archive.org", "w3.org", "irs.gov", "usa.gov", "gov.uk", "nih.gov",
    "cdc.gov", "who.int", "un.org", "harvard.edu", "mit.edu", "stanford.edu", "ox.ac.uk",
    "cam.ac.uk", "openai.com", "anthropic.com", "claude.ai", "duckduckgo.com", "baidu.com",
    "yandex.ru", "naver.com", "samsung.com", "sony.com", "hp.com", "dell.com", "lenovo.com",
    "gmail.com", "outlook.com", "hotmail.com", "proton.me", "office365.com", "sharepoint.com",
    "onedrive.com", "googleapis.com", "gstatic.com", "akamai.com", "fastly.com", "verizon.com",
    "att.com", "t-mobile.com", "comcast.com", "xfinity.com", "espn.com", "nfl.com", "nba.com",
    "craigslist.org", "indeed.com", "glassdoor.com", "zillow.com", "venmo.com", "wise.com",
    "revolut.com", "monzo.com", "santander.co.uk", "lloydsbank.com", "natwest.com",
}

RISKY_ATTACHMENT_EXTENSIONS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "pif", "jar", "msi", "iso",
    "img", "vhd", "lnk", "hta", "wsf", "ps1", "cpl", "reg", "docm", "xlsm", "pptm", "dotm",
    "xlam", "html", "htm", "shtml", "svg", "one", "chm", "appx", "msix",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "cab", "ace", "arj"}

# Visual homoglyph substitutions used in typosquats (lookalike -> canonical letter).
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s",
    "!": "i", "|": "l",
}
MULTI_CHAR_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))
