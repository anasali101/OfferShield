"""Shared brand, domain and free-email reference data.

This is intentionally a static reference list, not a live database. It is used
for similarity checks and email-domain consistency checks. A match here is
evidence of a claim, never proof of a recruiter's identity.
"""

from __future__ import annotations

KNOWN_BRANDS: dict[str, dict] = {
    "microsoft": {"display": "Microsoft", "domains": ["microsoft.com"]},
    "google": {"display": "Google", "domains": ["google.com", "abc.xyz"]},
    "amazon": {"display": "Amazon", "domains": ["amazon.com", "amazon.in"]},
    "tcs": {"display": "TCS", "domains": ["tcs.com"]},
    "tata consultancy services": {"display": "Tata Consultancy Services", "domains": ["tcs.com"]},
    "infosys": {"display": "Infosys", "domains": ["infosys.com"]},
    "wipro": {"display": "Wipro", "domains": ["wipro.com"]},
    "accenture": {"display": "Accenture", "domains": ["accenture.com"]},
    "hcl": {"display": "HCL", "domains": ["hcltech.com", "hcl.com"]},
    "hcltech": {"display": "HCLTech", "domains": ["hcltech.com"]},
    "cognizant": {"display": "Cognizant", "domains": ["cognizant.com"]},
    "capgemini": {"display": "Capgemini", "domains": ["capgemini.com"]},
    "ibm": {"display": "IBM", "domains": ["ibm.com"]},
    "deloitte": {"display": "Deloitte", "domains": ["deloitte.com"]},
    "kpmg": {"display": "KPMG", "domains": ["kpmg.com"]},
    "pwc": {"display": "PwC", "domains": ["pwc.com"]},
    "ey": {"display": "EY", "domains": ["ey.com"]},
    "flipkart": {"display": "Flipkart", "domains": ["flipkart.com"]},
    "swiggy": {"display": "Swiggy", "domains": ["swiggy.com"]},
    "zomato": {"display": "Zomato", "domains": ["zomato.com"]},
    "paytm": {"display": "Paytm", "domains": ["paytm.com"]},
    "phonepe": {"display": "PhonePe", "domains": ["phonepe.com"]},
    "razorpay": {"display": "Razorpay", "domains": ["razorpay.com"]},
    "hdfc bank": {"display": "HDFC Bank", "domains": ["hdfcbank.com"]},
    "icici bank": {"display": "ICICI Bank", "domains": ["icicibank.com"]},
    "reliance": {"display": "Reliance", "domains": ["ril.com"]},
    "jio": {"display": "Jio", "domains": ["jio.com"]},
    "adani": {"display": "Adani", "domains": ["adani.com"]},
    "tech mahindra": {"display": "Tech Mahindra", "domains": ["techmahindra.com"]},
    "larsen & toubro": {"display": "Larsen & Toubro", "domains": ["larsentoubro.com"]},
    "mphasis": {"display": "Mphasis", "domains": ["mphasis.com"]},
    "zoho": {"display": "Zoho", "domains": ["zoho.com"]},
    "freshworks": {"display": "Freshworks", "domains": ["freshworks.com"]},
    "byju's": {"display": "BYJU'S", "domains": ["byjus.com"]},
    "unacademy": {"display": "Unacademy", "domains": ["unacademy.com"]},
    "vedantu": {"display": "Vedantu", "domains": ["vedantu.com"]},
    "naukri": {"display": "Naukri", "domains": ["naukri.com"]},
    "linkedin": {"display": "LinkedIn", "domains": ["linkedin.com"]},
    "meta": {"display": "Meta", "domains": ["meta.com"]},
    "facebook": {"display": "Facebook", "domains": ["facebook.com"]},
    "apple": {"display": "Apple", "domains": ["apple.com"]},
    "oracle": {"display": "Oracle", "domains": ["oracle.com"]},
    "sap": {"display": "SAP", "domains": ["sap.com"]},
    "salesforce": {"display": "Salesforce", "domains": ["salesforce.com"]},
    "adobe": {"display": "Adobe", "domains": ["adobe.com"]},
    "nvidia": {"display": "NVIDIA", "domains": ["nvidia.com"]},
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.in",
    "hotmail.com", "outlook.com", "live.com", "msn.com", "rediffmail.com",
    "protonmail.com", "proton.me", "mail.com", "gmx.com", "zoho.in",
    "yandex.com", "aol.com", "icloud.com", "me.com", "163.com", "qq.com",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "buzz", "click", "link", "work", "live", "online", "site",
    "icu", "rest", "cam", "cf", "gq", "tk", "ml", "ga", "zip", "mov", "country",
    "stream", "download", "racing", "win", "bid", "loan",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd", "cutt.ly",
    "shorturl.at", "tiny.cc", "ow.ly", "buff.ly", "rebrand.ly", "s.id",
    "t.ly", "shorte.st", "adf.ly",
}

FREE_HOSTING_DOMAINS = {
    "pages.dev", "netlify.app", "vercel.app", "web.app", "firebaseapp.com",
    "blogspot.com", "wixsite.com", "weebly.com", "godaddysites.com",
    "000webhostapp.com", "glitch.me", "repl.co", "onrender.com", "surge.sh",
    "github.io", "gitlab.io", "wordpress.com", "site123.me",
}
