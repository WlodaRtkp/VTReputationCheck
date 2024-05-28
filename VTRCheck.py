import csv
import requests
import ipaddress


vt_api_key = "VT_API_key"
file_path = "data.csv"

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False  
    except ValueError:
        pass 

    if len(domain) > 255:
        return False
    if domain[-1] == ".":
        domain = domain[:-1]  
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    if all(c in allowed for c in domain) and domain.count('.') >= 1:
        parts = domain.split('.')
        if all(part for part in parts):  
            return True
    return False
def is_valid_hash(hash_str):
    return len(hash_str) in {32, 40, 64} and all(c in '0123456789abcdefABCDEF' for c in hash_str)

def get_reputation(url):
    headers = {
        "x-apikey": vt_api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        return malicious_votes
    else:
        return f"HTTP Error: {response.status_code}"

def check_type(user_choice, identifier):
    if user_choice == '1':  
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{identifier}"
    elif user_choice == '2':  
        url = f"https://www.virustotal.com/api/v3/domains/{identifier}"
    elif user_choice == '3': 
        url = f"https://www.virustotal.com/api/v3/files/{identifier}"
    return get_reputation(url)

def main():
    user_choice = input("Hey, do you want to perform an IP, domain, or hash check? Select 1 for IP, 2 for domain, and 3 for hash: ")
    if user_choice not in ['1', '2', '3']:
        print("Invalid choice. Exiting.")
        return

    with open(file_path, "r") as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            identifier = row[0]  

            if (user_choice == '1' and is_valid_ip(identifier)) or \
               (user_choice == '2' and is_valid_domain(identifier)) or \
               (user_choice == '3' and is_valid_hash(identifier)):
                malicious_count = check_type(user_choice, identifier)
                print(f"{identifier}: {malicious_count} vendors flagged this as malicious.")
            else:
                print(f"Invalid input for selected type: {identifier}")

if __name__ == "__main__":
    main()
                
