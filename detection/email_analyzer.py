import re
from email.utils import parseaddr
from .url_analyzer import analyze_url, extract_urls

KEYWORDS=["urgent action required","verify your account","password expired","your account is suspended","congratulations, you won","claim your reward","click immediately","update payment details","confirm your identity","bank account blocked","unusual login attempt","free gift","limited time offer"]
URGENCY=["urgent","immediately","right now","within one hour","today","act now","suspended","avoid losing","legal action","final notice","expires"]
GENERIC=["dear customer","hello customer","dear user","dear applicant","dear account holder"]
FREE_EMAIL={"gmail.com","yahoo.com","outlook.com","hotmail.com","proton.me","icloud.com"}

def analyze_email(sender, subject, body):
    text=f"{subject}\n{body}"; low=text.lower(); flags=[]; explanations=[]; score=0; seen=set()
    def add(key,title,detail,weight):
        nonlocal score
        if key in seen:return
        seen.add(key); score+=weight; flags.append({"title":title,"detail":detail,"weight":weight}); explanations.append(f"{title}: {detail} (+{weight}).")
    keywords=[k for k in KEYWORDS if k in low]
    if keywords: add("keyword", "High-risk phrases", "Found: "+", ".join(keywords), min(20,5+3*len(keywords)))
    urls=extract_urls(text)
    if urls: add("links","Links present",f"Found {len(urls)} link(s); destinations were analyzed statically only.",5)
    risky=[]
    for u in urls:
        a=analyze_url(u)
        if a["score"]>=10: risky.append((u,a))
    if risky: add("risky_url","Suspicious URL patterns",f"{len(risky)} link(s) show warning patterns, including {risky[0][1]['indicators'][0]}.",min(25,10+5*(len(risky)-1)))
    name,address=parseaddr(sender); sender_domain=address.rsplit("@",1)[-1].lower() if "@" in address else ""
    if not address or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",address): add("sender_invalid","Sender address format","The sender field is missing a conventional email address.",8)
    if name and sender_domain and any(b in name.lower() for b in ("bank","support","security","microsoft","paypal")) and not any(b in sender_domain for b in ("bank","microsoft","paypal")):
        add("display_mismatch","Display-name / sender mismatch",f"The display name suggests a trusted service but the sender domain is {sender_domain}.",15)
    if sender_domain and sender_domain in FREE_EMAIL and any(w in low for w in ["bank account","payment details","password","verify your account"]):
        add("sender_domain","Sender domain needs verification",f"Sender domain is {sender_domain}; this alone does not establish legitimacy.",7)
    if any(g in low for g in GENERIC): add("generic","Generic greeting","The message addresses a broad recipient rather than identifying you.",5)
    urgent=[w for w in URGENCY if w in low]
    if urgent: add("urgency","Pressure or threat language","Detected urgency cues: "+", ".join(urgent[:5]),min(15,5+2*len(urgent)))
    if re.search(r"\b(password|passcode|one[- ]time code|OTP|PIN)\b",low) and re.search(r"\b(reply|send|share|enter|confirm|provide)\b",low): add("credentials","Credential or code request","The message asks the reader to provide a password, code, or PIN.",22)
    if re.search(r"\b(bank account|credit card|payment details|wire transfer|gift card|fee)\b",low): add("financial","Financial information or payment request","The text refers to sensitive payment or account information.",12)
    if re.search(r"\b(attach(?:ed|ment)?|open the file|download the file)\b",low): add("attachment","Attachment mention","Unexpected attachments can carry malware; this tool does not open or download files.",10)
    if re.search(r"\b(congratulations|winner|won|prize|reward|free gift)\b",low): add("prize","Unexpected prize or offer","Unexpected rewards are commonly used to prompt risky action.",10)
    score=min(100,score)
    risk="LOW" if score<25 else "MEDIUM" if score<50 else "HIGH" if score<75 else "CRITICAL"
    meaningful=any(flag["weight"]>=8 and flag["title"]!="Links present" for flag in flags)
    verdict="PHISHING" if score>=50 and len(flags)>=3 else "SUSPICIOUS" if score>=10 or meaningful else "SAFE"
    if not flags: explanations=["No meaningful indicators from this limited rule set were detected."]
    recommendations=["Do not click links or open unexpected attachments.","Do not provide passwords, one-time codes, or payment details in response to a message.","Verify the request using a known official contact method.","Report suspected phishing to your organization or email provider."] if verdict!="SAFE" else ["A low score does not prove the message is safe.","Verify unexpected requests through a trusted channel and keep software updated."]
    return {"verdict":verdict,"score":score,"risk":risk,"keywords":keywords,"urls":urls,"flags":flags,"explanations":explanations,"recommendations":recommendations}
