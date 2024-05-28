import csv
import requests

vt_api_key = "VT_API_key"
file_path = "data.csv"

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
            malicious_count = check_type(user_choice, identifier)
            print(f"{identifier}: {malicious_count} vendors flagged this as malicious.")

if __name__ == "__main__":
    main()
