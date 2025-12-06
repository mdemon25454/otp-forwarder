#!/usr/bin/env python3
"""
Simple Telegram OTP forwarder for https://sms.stats.tel/
- Logs in using username/password
- Fetches new OTP messages
- Sends them directly to your Telegram bot
- Avoids duplicates
"""

import time
import logging
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import phonenumbers
from telegram import Bot, ParseMode

# -------------------------
# Configuration
# -------------------------
BOT_TOKEN = "8013216408:AAEzn1aISOgTAeqAPjJpeSV90B-WoY60bC0"  # আপনার bot token বসান
CHAT_ID = -1003009238534               # Telegram chat ID (আপনার নিজের বটে)

USERNAME = "Parves683"
PASSWORD = "Parves537#"
LOGIN_URL = "https://sms.stats.tel/"
FETCH_URL = "https://sms.stats.tel/portal/live/my_sms"

POLL_INTERVAL = 10  # seconds

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("otp_forwarder")

bot = Bot(token=BOT_TOKEN)

# -------------------------
# Helpers
# -------------------------
def get_country_info(number_raw: str) -> str:
    try:
        if not number_raw:
            return "Unknown"
        parsed = phonenumbers.parse(number_raw, None)
        region = phonenumbers.region_code_for_number(parsed)
        if not region:
            return "Unknown"
        flag = "".join(chr(127397 + ord(c)) for c in region.upper())
        country_name = phonenumbers.geocoder.description_for_number(parsed, "en") or region
        return f"{flag} {country_name} ({region})"
    except:
        return "Unknown"

def login_and_fetch():
    """Login to sms.stats.tel and fetch messages page"""
    session = requests.Session()
    login_data = {"username": USERNAME, "password": PASSWORD}
    try:
        session.get(LOGIN_URL, timeout=15)
        session.post(LOGIN_URL, data=login_data, timeout=15)
        resp = session.get(FETCH_URL, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        logger.error("Login/fetch error: %s", e)
        return None

def parse_messages(html: str):
    """Parse messages from HTML and return list of dicts"""
    if not html:
        return []
    soup = BeautifulSoup(html, "lxml")
    results = []

    # Simple heuristic: find all table rows or div rows
    rows = soup.select("table tr") or soup.select(".sms-row") or soup.select(".message-item")
    if not rows:
        # fallback: scan for OTPs in text
        text = soup.get_text("\n", strip=True)
        import re
        matches = re.findall(r"(\+?\d{6,15}).{0,40}?([0-9]{3,8}(?:[-\s][0-9]{2,6})?)", text)
        for m in matches:
            number = m[0]
            otp = m[1]
            results.append({
                "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "number": number,
                "service": "unknown",
                "otp": otp,
                "msg": f"OTP {otp} from {number}"
            })
        return results

    for r in rows:
        try:
            t_el = r.select_one(".time") or r.select_one("td.time")
            n_el = r.select_one(".number") or r.select_one("td.number")
            s_el = r.select_one(".service") or r.select_one("td.service")
            m_el = r.select_one(".body") or r.select_one("td.body") or r

            time_text = t_el.get_text(strip=True) if t_el else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            number_text = n_el.get_text(strip=True) if n_el else ""
            service_text = s_el.get_text(strip=True) if s_el else "unknown"
            body_text = m_el.get_text(" ", strip=True) if m_el else ""

            import re
            otp_match = re.search(r"([0-9]{3,8}(?:[-\s][0-9]{2,6})?)", body_text)
            otp_text = otp_match.group(1) if otp_match else ""
            if otp_text:
                results.append({
                    "time": time_text,
                    "number": number_text,
                    "service": service_text,
                    "otp": otp_text,
                    "msg": body_text
                })
        except:
            continue

    return results

def format_message(msg: dict) -> str:
    country_info = get_country_info(str(msg.get("number", "")))
    return (
        f"🔐 <b>OTP Received</b>\n\n"
        f"🕓 <b>Time:</b> {msg.get('time')}\n"
        f"📱 <b>Number:</b> {msg.get('number')}\n"
        f"🌍 <b>Country:</b> {country_info}\n"
        f"💬 <b>Service:</b> {msg.get('service')}\n"
        f"🔑 <b>OTP:</b> {msg.get('otp')}\n"
        f"📝 {msg.get('msg')}"
    )

def send_to_telegram(message_html: str):
    try:
        bot.send_message(chat_id=CHAT_ID, text=message_html, parse_mode=ParseMode.HTML)
        logger.info("✅ Message sent to Telegram")
    except Exception as e:
        logger.error("❌ Failed to send message: %s", e)

# -------------------------
# Main loop
# -------------------------
def main():
    logger.info("Starting OTP forwarder...")
    sent_keys = set()

    while True:
        try:
            html = login_and_fetch()
            messages = parse_messages(html)
            for m in messages:
                key = f"{m.get('number')}__{m.get('otp')}"
                if key in sent_keys:
                    continue
                send_to_telegram(format_message(m))
                sent_keys.add(key)

            # keep last 1000 to avoid memory growth
            if len(sent_keys) > 1000:
                sent_keys = set(list(sent_keys)[-1000:])

        except KeyboardInterrupt:
            logger.info("Stopped by user")
            break
        except Exception as e:
            logger.error("Main loop error: %s", e)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()