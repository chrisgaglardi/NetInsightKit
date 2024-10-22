import subprocess
import socket
import whois
import geoip2.database
import dns.resolver
import colorama
from colorama import Fore, Style
import time
import asyncio
import datetime
import json
import os
import requests
import argparse

colorama.init(autoreset=True)

async def traceroute(domain):
    try:
        print(Fore.CYAN + f"Starting traceroute for domain: {domain}")
        process = await asyncio.create_subprocess_exec(
            'tracert', domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            result = stdout.decode()
            print(Fore.GREEN + "Traceroute completed successfully.")
            return result
        else:
            print(Fore.RED + f"Traceroute failed: {stderr.decode()}")
            return "Traceroute failed"
    except Exception as e:
        print(Fore.RED + f"Traceroute operation failed: {e}")
        return "Traceroute operation failed"


def get_mx_records(domain):
    try:
        print(Fore.CYAN + f"Retrieving MX records for domain: {domain}")
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(record.exchange).rstrip('.') for record in mx_records]
        print(Fore.GREEN + f"MX records found: {mx_hosts}")
        return mx_hosts
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
        print(Fore.RED + f"MX records lookup failed: {e}")
        return []


def get_ip(domain):
    try:
        print(Fore.CYAN + f"Resolving IP for domain: {domain}")
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"IP address found: {ip}")
        return ip
    except socket.gaierror as e:
        print(Fore.RED + f"IP lookup failed: {e}")
        return "IP lookup failed"


def get_whois_info(domain):
    try:
        print(Fore.CYAN + f"Performing WHOIS lookup for domain: {domain}")
        w = whois.whois(domain)
        print(Fore.GREEN + "WHOIS lookup completed successfully.")
        return w
    except Exception as e:
        print(Fore.RED + f"WHOIS lookup failed: {e}")
        return "WHOIS lookup failed"


def get_geolocation(ip, database='City'):
    try:
        if database == 'City':
            db_path = 'data/GeoLite2-City.mmdb'
        elif database == 'Country':
            db_path = 'data/GeoLite2-Country.mmdb'
        elif database == 'ASN':
            db_path = 'data/GeoLite2-ASN.mmdb'
        else:
            raise ValueError("Unknown database type")

        print(Fore.CYAN + f"Performing {database} geolocation lookup for IP: {ip}")
        with geoip2.database.Reader(db_path) as reader:
            if database == 'City':
                response = reader.city(ip)
                geo_data = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                }
            elif database == 'Country':
                response = reader.country(ip)
                geo_data = {
                    'country': response.country.name
                }
            elif database == 'ASN':
                response = reader.asn(ip)
                geo_data = {
                    'autonomous_system_number': response.autonomous_system_number,
                    'autonomous_system_organization': response.autonomous_system_organization
                }
            print(Fore.GREEN + f"{database} geolocation lookup completed successfully.")
            return geo_data
    except FileNotFoundError:
        print(Fore.RED + f"GeoLite2 {database} database file not found. Ensure '{db_path}' is in the 'data' directory.")
        return f"Geolocation database ({database}) not found"
    except Exception as e:
        print(Fore.RED + f"Geolocation lookup ({database}) failed: {e}")
        return f"Geolocation lookup ({database}) failed"


def reverse_dns_lookup(ip):
    try:
        print(Fore.CYAN + f"Performing reverse DNS lookup for IP: {ip}")
        hostname = socket.gethostbyaddr(ip)
        print(Fore.GREEN + f"Reverse DNS lookup successful: {hostname[0]}")
        return hostname[0]
    except socket.herror as e:
        print(Fore.RED + f"Reverse DNS lookup failed: {e}")
        return "Reverse DNS lookup failed"


def port_scan(ip):
    try:
        print(Fore.CYAN + f"Starting port scan for IP: {ip}")
        result = subprocess.run(
            ['nmap', '-Pn', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            print(Fore.GREEN + "Port scan completed successfully.")
            return result.stdout
        else:
            print(Fore.RED + f"Port scan failed: {result.stderr}")
            return "Port scan failed"
    except FileNotFoundError:
        print(Fore.YELLOW + f"Skipping port scan for IP: {ip} because 'nmap' is not installed or not found in PATH.")
        return "Port scan skipped (nmap not found)"
    except Exception as e:
        print(Fore.RED + f"Port scan operation failed: {e}")
        return "Port scan operation failed"


def http_header_inspection(domain):
    try:
        print(Fore.CYAN + f"Inspecting HTTP headers for domain: {domain}")
        response = requests.get(f"http://{domain}", timeout=10)
        headers = response.headers
        print(Fore.GREEN + "HTTP header inspection completed successfully.")
        return headers
    except requests.RequestException as e:
        print(Fore.RED + f"HTTP header inspection failed: {e}")
        return "HTTP header inspection failed"


async def analyze_domain(domain, results):
    result = {}
    print(Fore.MAGENTA + f"\nStarting analysis for domain: {domain}")
    start_time = time.time()

    # Traceroute
    print(Fore.MAGENTA + f"\nTraceroute for domain {domain}:")
    traceroute_result = await traceroute(domain)
    result['traceroute'] = traceroute_result
    print(traceroute_result)

    # IP Lookup
    ip = get_ip(domain)
    result['ip'] = ip
    print(Fore.MAGENTA + f"\nIP address for domain: {ip}")

    # WHOIS Lookup
    print(Fore.MAGENTA + "\nWHOIS information for domain:")
    whois_info = get_whois_info(domain)
    result['whois'] = whois_info
    print(whois_info)

    # Geolocation Lookups
    print(Fore.MAGENTA + "\nGeolocation information for domain:")
    geo_city_info = get_geolocation(ip, 'City')
    result['geolocation_city'] = geo_city_info
    print(geo_city_info)

    geo_country_info = get_geolocation(ip, 'Country')
    result['geolocation_country'] = geo_country_info
    print(geo_country_info)

    geo_asn_info = get_geolocation(ip, 'ASN')
    result['geolocation_asn'] = geo_asn_info
    print(geo_asn_info)

    # Reverse DNS Lookup
    reverse_dns = reverse_dns_lookup(ip)
    result['reverse_dns'] = reverse_dns
    print(Fore.MAGENTA + f"\nReverse DNS Lookup for IP {ip}: {reverse_dns}")

    # Port Scan (synchronous)
    port_scan_result = port_scan(ip)
    result['port_scan'] = port_scan_result
    print(Fore.MAGENTA + f"\nPort Scan for IP {ip}:")
    print(port_scan_result)

    # HTTP Header Inspection
    http_headers = http_header_inspection(domain)
    result['http_headers'] = http_headers
    print(Fore.MAGENTA + f"\nHTTP Headers for domain {domain}: {http_headers}")

    # Store results
    result['analysis_time'] = time.time() - start_time
    results[domain] = result


def save_results(results, email):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_email = email.replace('@', '_at_').replace('.', '_')
    filename = f"results/scan_results_{sanitized_email}_{timestamp}.txt"
    os.makedirs('results', exist_ok=True)
    with open(filename, 'w') as file:
        for domain, data in results.items():
            file.write(f"\n=== Analysis for domain: {domain} ===\n")
            file.write(f"Traceroute:\n{data['traceroute']}\n")
            file.write(f"IP Address: {data['ip']}\n")
            file.write(f"WHOIS Information:\n{data['whois']}\n")
            file.write(f"City Geolocation Information:\n{data['geolocation_city']}\n")
            file.write(f"Country Geolocation Information:\n{data['geolocation_country']}\n")
            file.write(f"ASN Geolocation Information:\n{data['geolocation_asn']}\n")
            file.write(f"Reverse DNS Lookup:\n{data['reverse_dns']}\n")
            file.write(f"Port Scan:\n{data['port_scan']}\n")
            file.write(f"HTTP Headers:\n{data['http_headers']}\n")
            file.write(f"Total Analysis Time: {data['analysis_time']} seconds\n")
    print(Fore.GREEN + f"Results saved to {filename}")


def generate_summary(results):
    print(Fore.MAGENTA + "\n=== Summary of Analysis ===")
    num_domains = len(results)
    num_traceroute_failed = sum(1 for r in results.values() if "timed out" in r['traceroute'])
    geo_countries = [r['geolocation_country'].get('country') for r in results.values() if 'geolocation_country' in r]

    print(Fore.CYAN + f"Number of domains analyzed: {num_domains}")
    print(Fore.CYAN + f"Number of traceroutes that failed: {num_traceroute_failed}")
    print(Fore.CYAN + f"Countries identified: {set(geo_countries)}")


async def main():
    parser = argparse.ArgumentParser(description="Analyze email domain and its related information.")
    parser.add_argument('-a', '--email', type=str, help="Email address for analysis")
    args = parser.parse_args()

    if args.email:
        email = args.email
    else:
        email = input("Enter the email address for analysis: ")

    domain = email.split('@')[1]

    # Analyze the main domain
    print(Fore.MAGENTA + f"\nStarting analysis for main domain: {domain}")

    # Retrieve MX records
    mx_hosts = get_mx_records(domain)
    domains_to_analyze = [domain] + mx_hosts

    results = {}

    # Use asyncio to analyze domains concurrently
    await asyncio.gather(*(analyze_domain(d, results) for d in domains_to_analyze))

    # Save results to a timestamped text file
    save_results(results, email)

    # Generate summary
    generate_summary(results)

if __name__ == "__main__":
    asyncio.run(main())