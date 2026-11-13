import ipaddress
import re
from urllib.parse import urlsplit

SHORTENERS = {"bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rb.gy"}
SUSPICIOUS_TLDS = {"zip","mov","top","click","work","support","country","gq","tk","xyz"}
LOOKALIKE = ("paypa1","paypai","micros0ft","g00gle","amaz0n","appleid","secure-login","verify-account")
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")

def extract_urls(text):
    found=[]
    for match in URL_RE.findall(text or ""):
        cleaned=match.rstrip(".,!?;:)]}")
        if cleaned not in found: found.append(cleaned)
    return found[:25]

def analyze_url(raw):
    value=(raw or "").strip()
    if value.startswith("www."): value="http://"+value
    if not value or len(value)>2048: return {"valid":False,"url":raw,"hostname":"","scheme":"","score":0,"risk":"LOW","indicators":["Enter a URL under 2,048 characters."],"recommendations":["Paste a complete URL to analyze."]}
    try:
        parsed=urlsplit(value)
        host=(parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme not in ("http","https") or not host or any(c.isspace() for c in host): raise ValueError
    except Exception:
        return {"valid":False,"url":value,"hostname":"","scheme":"","score":0,"risk":"LOW","indicators":["URL format is invalid; provide an http:// or https:// address."],"recommendations":["Check the address carefully before analyzing it."]}
    indicators=[]; score=0
    def add(label, points):
        nonlocal score
        indicators.append(label); score+=points
    try: ipaddress.ip_address(host); add("Uses an IP address instead of a domain",24)
    except ValueError: pass
    if parsed.scheme=="http": add("Uses unencrypted HTTP",10)
    if parsed.username is not None or parsed.password is not None: add("Contains username or password before the hostname",25)
    if host.startswith("xn--") or ".xn--" in host: add("Contains punycode / internationalized domain labels",18)
    if host in SHORTENERS: add("Uses a known URL shortener that hides its destination",16)
    labels=host.split(".")
    if len(labels)>4: add("Has an unusually deep subdomain structure",12)
    if any(ch.isdigit() for ch in host) and not re.fullmatch(r"[0-9.]+",host): add("Domain mixes letters and digits",5)
    if any(term in host for term in LOOKALIKE): add("Contains a common brand lookalike or login-bait pattern",18)
    if labels[-1] in SUSPICIOUS_TLDS: add("Uses a higher-risk or uncommon top-level domain",8)
    if len(parsed.path)>90 or parsed.query.count("=")>8: add("Has an unusually complex URL path or query",6)
    if not indicators: indicators.append("No common static URL warning pattern detected.")
    score=min(score,100)
    risk="LOW" if score<25 else "MEDIUM" if score<50 else "HIGH" if score<75 else "CRITICAL"
    recommendations=["Do not open a suspicious link; navigate to the known official site yourself.","A static scan does not check live content or prove safety."] if score else ["Still verify the sender and destination through a trusted channel.","No live website request was made."]
    return {"valid":True,"url":value,"hostname":host,"scheme":parsed.scheme,"score":score,"risk":risk,"indicators":indicators,"recommendations":recommendations}
