from scapy.all import *
from scapy.layers.inet import TCP, IP
import re
import chardet
import html
from urllib.parse import unquote
from datetime import datetime
from env import INTERFACE, TARGET_PORT as PORT

FILTER = f"tcp port {PORT}"

XSS_VULNERABILITIES = {
    "Stored XSS": {
        r"<script.*?>.*?</script>": {
            "description": "Script Injection",
            "explanation": "Injection of JavaScript via <script> tag.",
        },
        r"<img.*?onerror=['\"].*?['\"].*?>": {
            "description": "Image Injection via onerror",
            "explanation": "Injection through <img> tag using onerror attribute.",
        }
    },
    "Reflected XSS": {
        r"javascript:\s*alert\(.*?\)": {
            "description": "JavaScript Alert Injection",
            "explanation": "Injection using JavaScript alert().",
        },
        r"javascript:\s*eval\(.*?\)": {
            "description": "JavaScript Eval Injection",
            "explanation": "Injection using JavaScript eval().",
        }
    },
}

def decode_payload(payload) -> str:
    decoded_payload = html.unescape(payload)
    decoded_payload = unquote(decoded_payload)
    return decoded_payload

def packet_parser_callback(packet: Packet) -> None:
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].dport == PORT or packet[TCP].sport == PORT:
            if packet.haslayer(Raw):
                try:
                    raw_data = packet.getlayer(Raw).load
                    detected_encoding = chardet.detect(raw_data).get("encoding", "utf-8")
                    payload = raw_data.decode(encoding=detected_encoding, errors="ignore")
                    payload = decode_payload(payload)

                    found_vulnerabilities = []
                    for category, patterns in XSS_VULNERABILITIES.items():
                        for pattern, vulnerability in patterns.items():
                            matches = re.findall(pattern, payload, re.IGNORECASE)
                            if matches:
                                found_vulnerabilities.append(f"[Vulnerability <{category}: {vulnerability['description']}> detected]")
                    if found_vulnerabilities:
                        print(f"[+] HTTP packet: {datetime.fromtimestamp(packet.time).strftime('%d-%m-%Y %H:%M:%S')} src: {packet[IP].src}, dst: {packet[IP].dst}")
                        print('\n'.join(found_vulnerabilities))
                except UnicodeDecodeError:
                    pass

if __name__ == '__main__':
    print(f"Listening on {INTERFACE}, filtering {FILTER}...")
    sniff(iface=INTERFACE, filter=FILTER, prn=packet_parser_callback, store=0)
