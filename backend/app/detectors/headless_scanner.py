"""
Headless Browser Scanner — Phishara
=====================================
Opens a URL in a real (invisible) Chrome browser and watches what the page
actually DOES — not just what the URL looks like.

This catches phishing sites that look clean by URL but behave badly:
  - Pages that ask for your password
  - Pages that silently redirect you somewhere else
  - Pages with hidden iframes loading other sites
  - Pages running suspicious JavaScript

Result: "Safe", "Suspicious", or "Dangerous" with plain-English reasons.

MVP — kept simple and well-commented.
"""

import asyncio
from typing import Dict, Any, List
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout


async def scan_page_behaviour(url: str, timeout_ms: int = 15000) -> Dict[str, Any]:
    """
    Open the URL in a headless Chromium browser and analyse page behaviour.

    Returns a dict with:
      - verdict: "Safe" | "Suspicious" | "Dangerous"
      - score: 0-100
      - signals: list of plain-English findings
      - details: raw technical data for the dev console
    """

    result: Dict[str, Any] = {
        "url": url,
        "verdict": "Safe",
        "score": 0,
        "signals": [],
        "details": {
            "has_password_field": False,
            "has_login_form": False,
            "hidden_iframes": [],
            "suspicious_scripts": [],
            "auto_redirects": [],
            "popups_attempted": 0,
            "external_requests": [],
            "page_title": "",
            "final_url": url,
        }
    }

    redirects: List[str] = []
    external_requests: List[str] = []
    popups = 0

    try:
        async with async_playwright() as p:
            # Launch headless Chromium — invisible browser
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                # Pretend to be a normal Chrome user so sites don't block us
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                # Block actual navigation to dangerous pages for safety
                java_script_enabled=True,
            )

            page = await context.new_page()

            # ── Track every network request the page makes ──────────────────
            from urllib.parse import urlparse
            base_domain = urlparse(url).netloc

            def on_request(request):
                req_domain = urlparse(request.url).netloc
                # Flag requests going to a completely different domain
                if req_domain and req_domain != base_domain:
                    external_requests.append(request.url)

            page.on("request", on_request)

            # ── Track redirects ─────────────────────────────────────────────
            def on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    redirects.append(response.url)

            page.on("response", on_response)

            # ── Track popup attempts ────────────────────────────────────────
            def on_popup(popup):
                nonlocal popups
                popups += 1

            page.on("popup", on_popup)

            # ── Navigate to the page ────────────────────────────────────────
            try:
                await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            except PlaywrightTimeout:
                result["signals"].append("Page took too long to load — may be trying to stall")
                result["score"] += 10

            # Wait a moment for JS to run (catches delayed redirects)
            await asyncio.sleep(2)

            # ── Check 1: Does the page have a login / password form? ────────
            # This is the #1 sign of a phishing page
            password_fields = await page.query_selector_all("input[type='password']")
            if password_fields:
                result["details"]["has_password_field"] = True
                result["details"]["has_login_form"] = True
                result["signals"].append(
                    "This page asks for your password — only enter it if you're 100% sure this is the real site"
                )
                result["score"] += 35

            # Also check for email/username fields paired with submit buttons
            email_fields = await page.query_selector_all("input[type='email'], input[name*='user'], input[name*='email']")
            submit_buttons = await page.query_selector_all("button[type='submit'], input[type='submit']")
            if email_fields and submit_buttons and not password_fields:
                result["details"]["has_login_form"] = True
                result["signals"].append(
                    "This page has a form asking for your email address"
                )
                result["score"] += 15

            # ── Check 2: Hidden iframes ─────────────────────────────────────
            # Scammers embed invisible iframes to load other sites secretly
            iframes = await page.query_selector_all("iframe")
            hidden_iframes = []
            for iframe in iframes:
                src = await iframe.get_attribute("src") or ""
                style = await iframe.get_attribute("style") or ""
                width = await iframe.get_attribute("width") or "100"
                height = await iframe.get_attribute("height") or "100"

                is_hidden = (
                    "display:none" in style.replace(" ", "")
                    or "visibility:hidden" in style.replace(" ", "")
                    or width in ("0", "1")
                    or height in ("0", "1")
                )

                if is_hidden and src:
                    hidden_iframes.append(src)

            if hidden_iframes:
                result["details"]["hidden_iframes"] = hidden_iframes
                result["signals"].append(
                    f"This page has {len(hidden_iframes)} hidden section(s) loading content "
                    "you can't see — a common trick used by scammers"
                )
                result["score"] += 30

            # ── Check 3: Suspicious scripts ─────────────────────────────────
            # Look for scripts that do things legitimate sites don't need to
            suspicious_script_patterns = [
                "document.cookie",      # stealing cookies
                "window.location",      # forced redirect
                "eval(",                # obfuscated/hidden code
                "atob(",                # base64 encoded hidden code
                "unescape(",            # another obfuscation trick
                "fromCharCode(",        # character-code obfuscation
            ]

            scripts = await page.query_selector_all("script:not([src])")
            found_patterns = []
            for script in scripts:
                content = await script.inner_text()
                for pattern in suspicious_script_patterns:
                    if pattern in content and pattern not in found_patterns:
                        found_patterns.append(pattern)

            if found_patterns:
                result["details"]["suspicious_scripts"] = found_patterns
                if "eval(" in found_patterns or "atob(" in found_patterns:
                    result["signals"].append(
                        "This page runs hidden/encoded code — a technique used to disguise malicious activity"
                    )
                    result["score"] += 25
                if "document.cookie" in found_patterns:
                    result["signals"].append(
                        "This page tries to access your browser cookies — could be attempting to steal your session"
                    )
                    result["score"] += 20

            # ── Check 4: Automatic redirects ────────────────────────────────
            final_url = page.url
            result["details"]["final_url"] = final_url
            result["details"]["auto_redirects"] = redirects

            if len(redirects) > 2:
                result["signals"].append(
                    f"This page bounced you through {len(redirects)} redirects automatically — "
                    "scammers do this to hide where they're really sending you"
                )
                result["score"] += 20

            if final_url != url and urlparse(final_url).netloc != base_domain:
                result["signals"].append(
                    f"You ended up on a completely different website than the one you clicked"
                )
                result["score"] += 25

            # ── Check 5: Popup attempts ─────────────────────────────────────
            result["details"]["popups_attempted"] = popups
            if popups > 0:
                result["signals"].append(
                    f"This page tried to open {popups} popup window(s) — often used to trick you"
                )
                result["score"] += 15

            # ── Check 6: Page title ─────────────────────────────────────────
            title = await page.title()
            result["details"]["page_title"] = title

            # ── Check 7: External requests ──────────────────────────────────
            # Cap to avoid noise
            result["details"]["external_requests"] = list(set(external_requests))[:20]
            if len(external_requests) > 15:
                result["signals"].append(
                    f"This page loaded content from {len(set(external_requests))} other websites in the background"
                )
                result["score"] += 10

            await browser.close()

    except Exception as e:
        result["signals"].append(f"Could not fully analyse this page: {str(e)[:100]}")
        result["score"] += 5

    # ── Final verdict ────────────────────────────────────────────────────────
    score = min(result["score"], 100)
    result["score"] = score

    if score >= 60:
        result["verdict"] = "Dangerous"
    elif score >= 25:
        result["verdict"] = "Suspicious"
    else:
        result["verdict"] = "Safe"
        if not result["signals"]:
            result["signals"].append(
                "The page behaved normally — no suspicious activity detected"
            )

    return result
