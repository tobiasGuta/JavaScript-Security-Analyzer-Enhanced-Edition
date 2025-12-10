# -*- coding: utf-8 -*-
from lib.connection.response import BaseResponse

class WAF:
    SIGNATURES = {
        "Cloudflare": lambda r: "cloudflare" in r.headers.get("server", "").lower() or "cf-ray" in r.headers,
        "CloudFront": lambda r: "cloudfront" in r.headers.get("server", "").lower() or "cloudfront" in r.headers.get("via", "").lower() or "x-amz-cf-id" in r.headers,
        "Incapsula": lambda r: "Incapsula" in r.headers.get("X-CDN", "") or "visid_incap" in r.headers.get("set-cookie", ""),
        "Akamai": lambda r: "AkamaiGHost" in r.headers.get("server", "") or "AkamaiGHost" in r.headers.get("X-Cache", ""),
        "F5 BIG-IP APM": lambda r: "BigIP" in r.headers.get("set-cookie", "") or "MRHSession" in r.headers.get("set-cookie", ""),
        "Sucuri": lambda r: "sucuri" in r.headers.get("x-sucuri-id", "").lower() or "sucuri" in r.headers.get("server", "").lower(),
        "Barracuda": lambda r: "barra_counter_session" in r.headers.get("set-cookie", "") or "BNI__BARRACUDA_LB_COOKIE" in r.headers.get("set-cookie", ""),
        "Imperva": lambda r: "incap_ses" in r.headers.get("set-cookie", "") or "visid_incap" in r.headers.get("set-cookie", ""),
    }

    @staticmethod
    def detect(response: BaseResponse) -> str | None:
        # Check headers case-insensitively
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Helper to check header presence or value
        def check_header(key, value=None):
            if key.lower() not in headers:
                return False
            if value:
                return value.lower() in headers[key.lower()].lower()
            return True

        if check_header("server", "cloudflare") or check_header("cf-ray"):
            return "Cloudflare"
        if check_header("server", "cloudfront") or check_header("via", "cloudfront") or check_header("x-amz-cf-id"):
            return "CloudFront"
        if check_header("X-CDN", "Incapsula") or check_header("set-cookie", "visid_incap"):
            return "Incapsula"
        if check_header("server", "AkamaiGHost") or check_header("X-Cache", "AkamaiGHost"):
            return "Akamai"
        if check_header("set-cookie", "BigIP") or check_header("set-cookie", "MRHSession"):
            return "F5 BIG-IP APM"
        if check_header("x-sucuri-id") or check_header("server", "sucuri"):
            return "Sucuri"
        if check_header("set-cookie", "barra_counter_session") or check_header("set-cookie", "BNI__BARRACUDA_LB_COOKIE"):
            return "Barracuda"
        if check_header("set-cookie", "incap_ses") or check_header("set-cookie", "visid_incap"):
            return "Imperva"
            
        return None
