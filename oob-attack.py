import random

# Define a dictionary of categories and their corresponding out-of-band domains
oob_domains = {
    "project discovery": ["interact.sh", "oast.fun", "interactsh.com", "oast.site", "oast.me", "oast.live", "oast.online", "oast.pro"],
    "tenable": ["nessus.org"],
    "invicti": ["r87.me"],
    "xss hunter": ["xss.ht"],
    "acunetix": ["bxss.me"],
    "bxss hunter": ["bxss.in"],
    "burp": ["oastify.com"],
    "appcheck ng": ["ptst.io"],
    "xss report": ["xss.report"],
    "canarytokens": ["canarytokens.com"]
}

# Flatten the dictionary to a list of domains for easy random selection
all_domains = [domain for sublist in oob_domains.values() for domain in sublist]

# Define common types of attacks
attack_types = ['HTTP', 'DNS', 'SMTP', 'XSS', 'SQLi', 'XXE', 'Command Injection', 'RCE']

def simulate_http(domain):
    """ Simulate HTTP GET request. """
    try:
        print(f"Simulating HTTP request to {domain}.")
    except Exception as e:
        print(f"Error simulating HTTP request: {e}")

def simulate_dns(domain):
    """ Simulate DNS lookup. """
    try:
        print(f"Simulating DNS query for {domain}.")
    except Exception as e:
        print(f"Error simulating DNS lookup: {e}")

def simulate_smtp(domain):
    """ Simulate SMTP connection. """
    try:
        print(f"Simulating SMTP connection to smtp.{domain}.")
    except Exception as e:
        print(f"Error simulating SMTP connection: {e}")

def simulate_xss(domain):
    """ Simulate Cross-Site Scripting attack. """
    try:
        print(f"XSS payload injected to {domain}/vulnerable_page.")
    except Exception as e:
        print(f"Error simulating XSS: {e}")

def simulate_sqli(domain):
    """ Simulate SQL Injection attack. """
    try:
        print(f"SQLi payload executed against {domain}/db_query.")
    except Exception as e:
        print(f"Error simulating SQLi: {e}")

def simulate_xxe(domain):
    """ Simulate XML External Entity attack. """
    try:
        print(f"XXE payload sent to {domain}/xml_processor.")
    except Exception as e:
        print(f"Error simulating XXE: {e}")

def simulate_command_injection(domain):
    """ Simulate Command Injection attack. """
    try:
        print(f"Command injection executed on {domain}/cmd_exec.")
    except Exception as e:
        print(f"Error simulating Command Injection: {e}")

def simulate_rce(domain):
    """ Simulate Remote Code Execution. """
    try:
        print(f"RCE payload triggered on {domain}/app.")
    except Exception as e:
        print(f"Error simulating RCE: {e}")

def simulate_attack():
    # Randomly select a domain and an attack type
    selected_domain = random.choice(all_domains)
    selected_attack_type = random.choice(attack_types)
    
    # Execute the corresponding attack simulation
    print(f"Simulating {selected_attack_type} on {selected_domain}")
    attack_function = {
        'HTTP': simulate_http,
        'DNS': simulate_dns,
        'SMTP': simulate_smtp,
        'XSS': simulate_xss,
        'SQLi': simulate_sqli,
        'XXE': simulate_xxe,
        'Command Injection': simulate_command_injection,
        'RCE': simulate_rce
    }.get(selected_attack_type, lambda x: print("Unknown attack type"))

    # Call the function safely
    if attack_function:
        attack_function(selected_domain)

# Call the function to simulate the attack
simulate_attack()