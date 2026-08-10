TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "wikipedia.org",
    "apple.com",
    "amazon.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "stackoverflow.com",
    "python.org",
    "npmjs.com",
    "nodejs.org",
    "mozilla.org",
    "cloudflare.com",
    "paypal.com",
    "ebay.com",
    "netflix.com",
    "spotify.com",
    "adobe.com",
    "ibm.com",
    "intel.com",
    "cisco.com",
    "office.com",
    "outlook.com",
    "azure.com",
    "gmail.com",
    "drive.google.com",
    "docs.google.com",
    "bbc.com",
    "cnn.com",
}


def is_trusted_domain(hostname):
    """
    Returns True only when the hostname is the trusted
    domain itself or a subdomain of it.

    Examples:

        google.com              -> True
        www.google.com          -> True
        mail.google.com         -> True

        google.com.evil.com     -> False
        google-login.com        -> False
    """

    if not hostname:
        return False

    hostname = hostname.lower().strip(".")

    for domain in TRUSTED_DOMAINS:

        if hostname == domain:
            return True

        if hostname.endswith("." + domain):
            return True

    return False