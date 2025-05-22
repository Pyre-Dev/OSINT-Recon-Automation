import json
import argparse
from apis.shodan_lookup import search_shodan
from apis.abuseip_lookup import check_abuseip
from apis.hibp_lookup import check_hibp
from apis.virustotal_lookup import check_virustotal

with open("config.json") as f:
    config = json.load(f)

def print_results(title, result):
    print(f"\n🔹 {title}")
    for k, v in result.items():
        print(f"{k}: {v}")

def main():
    parser = argparse.ArgumentParser(description="OSINT Recon Tool")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-e", "--email", help="Target email address")
    args = parser.parse_args()

    if args.ip:
        print_results("Shodan IP Scan", search_shodan(args.ip, config["shodan_api_key"]))
        print_results("AbuseIPDB Reputation", check_abuseip(args.ip, config["abuseipdb_api_key"]))
        print_results("VirusTotal Intel", check_virustotal(args.ip, config["virustotal_api_key"]))

    if args.email:
        print_results("HaveIBeenPwned Email Breach Check", check_hibp(args.email, config["hibp_api_key"]))

if __name__ == "__main__":
    main()