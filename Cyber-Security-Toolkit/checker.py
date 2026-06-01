from urllib.parse import urlparse

def check_url(url):

    score = 0

    parsed = urlparse(url)

    if parsed.scheme == "https":
        score += 1

    if len(url) < 75:
        score += 1

    if "@" not in url:
        score += 1

    if parsed.netloc:
        score += 1

    if score >= 4:
        return "Safe"

    elif score >= 2:
        return "Suspicious"

    else:
        return "Unsafe"