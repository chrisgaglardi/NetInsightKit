import asyncio
import geoip2.database
from colorama import init, Fore, Style
import os
from datetime import datetime
import sys
import argparse
import aiofiles
import ipaddress
import socket
from ipwhois import IPWhois, exceptions as whois_exceptions
import csv
import json
import logging

# Initialize colorama for colored terminal output
init(autoreset=True)

# Configure logging to log messages to both console and a log file
LOGS_DIR = 'results'
os.makedirs(LOGS_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "script.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

# Paths to GeoLite2 databases
ASN_DB_PATH = os.path.join('data', 'GeoLite2-ASN.mmdb')
CITY_DB_PATH = os.path.join('data', 'GeoLite2-City.mmdb')
COUNTRY_DB_PATH = os.path.join('data', 'GeoLite2-Country.mmdb')

# Ensure results directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Function to get the current timestamp for logging and output purposes
def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Function to validate if the provided IP address is in the correct format
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to perform a reverse DNS lookup to find the hostname associated with an IP address
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = 'N/A'
    return hostname

# Function to get subnet information for an IP address
def get_subnet_info(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            # Create a /24 subnet for IPv4
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        else:
            # Create a /64 subnet for IPv6
            network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
        subnet = str(network)
    except ValueError:
        subnet = 'N/A'
    return subnet

# Function to retrieve WHOIS information about the IP address
def get_whois(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        registrar = res.get('registrar', 'N/A')
        creation_date = res.get('creation_date', 'N/A')
        expiration_date = res.get('expiration_date', 'N/A')
    except whois_exceptions.IPDefinedError:
        registrar = 'Private/Reserved IP'
        creation_date = 'N/A'
        expiration_date = 'N/A'
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {ip}: {e}")
        registrar = 'N/A'
        creation_date = 'N/A'
        expiration_date = 'N/A'
    return registrar, creation_date, expiration_date

# Class to manage the GeoIP readers for ASN, City, and Country
class GeoIPReaders:
    def __init__(self):
        try:
            # Load GeoLite2 databases
            print("Initializing GeoIP readers...")
            self.asn_reader = geoip2.database.Reader(ASN_DB_PATH)
            self.city_reader = geoip2.database.Reader(CITY_DB_PATH)
            self.country_reader = geoip2.database.Reader(COUNTRY_DB_PATH)
            print("GeoIP readers initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing GeoIP readers: {e}")
            sys.exit(1)
    
    # Close all GeoIP readers to free resources
    def close(self):
        print("Closing GeoIP readers...")
        self.asn_reader.close()
        self.city_reader.close()
        self.country_reader.close()
        print("GeoIP readers closed.")

# Asynchronous function to process an IP address and gather information
async def process_ip(ip, readers, output_format, semaphore, stats):
    # Semaphore is used to limit the number of concurrent tasks
    async with semaphore:
        timestamp = get_timestamp()
        logging.info(f"Processing IP: {ip}")
        stats['total_ips'] += 1

        # Dictionary to store collected data for the IP address
        data = {
            'IP Address': ip,
            'Hostname': get_hostname(ip),
            'Timestamp': timestamp,
            'ASN': 'N/A',
            'Organization': 'N/A',
            'Country': 'N/A',
            'City': 'N/A',
            'Latitude': 'N/A',
            'Longitude': 'N/A',
            'Time Zone': 'N/A',
            'Postal Code': 'N/A',
            'Subnet': get_subnet_info(ip),
            'Registrar': 'N/A',
            'Creation Date': 'N/A',
            'Expiration Date': 'N/A'
        }

        print(f"Starting data collection for IP: {ip}")

        # Get ASN and Organization information
        try:
            asn_response = readers.asn_reader.asn(ip)
            data['ASN'] = asn_response.autonomous_system_number
            data['Organization'] = asn_response.autonomous_system_organization
            print(f"ASN and organization data collected for IP: {ip}")
        except geoip2.errors.AddressNotFoundError:
            logging.warning(f"ASN data not found for IP: {ip}")

        # Get City and Country information
        try:
            city_response = readers.city_reader.city(ip)
            data['Country'] = city_response.country.name if city_response.country.name else 'N/A'
            data['City'] = city_response.city.name if city_response.city.name else 'N/A'
            data['Latitude'] = city_response.location.latitude if city_response.location.latitude else 'N/A'
            data['Longitude'] = city_response.location.longitude if city_response.location.longitude else 'N/A'
            data['Time Zone'] = city_response.location.time_zone if city_response.location.time_zone else 'N/A'
            data['Postal Code'] = city_response.postal.code if city_response.postal.code else 'N/A'
            print(f"City and country data collected for IP: {ip}")
        except geoip2.errors.AddressNotFoundError:
            logging.warning(f"City/Country data not found for IP: {ip}")

        # Get additional Country information if not already obtained
        if data['Country'] == 'N/A':
            try:
                country_response = readers.country_reader.country(ip)
                data['Country'] = country_response.country.name if country_response.country.name else 'N/A'
                print(f"Country data collected for IP: {ip}")
            except geoip2.errors.AddressNotFoundError:
                logging.warning(f"Country data not found for IP: {ip}")

        # Get WHOIS information about the IP address
        registrar, creation_date, expiration_date = get_whois(ip)
        data['Registrar'] = registrar
        data['Creation Date'] = creation_date
        data['Expiration Date'] = expiration_date
        print(f"WHOIS data collected for IP: {ip}")

        # Update stats based on WHOIS data
        if registrar != 'N/A' and registrar != 'Private/Reserved IP':
            stats['whois_info_count'] += 1

        # Display the data in colored format for readability
        print(f"{Fore.CYAN}--- Information for {ip} ---{Style.RESET_ALL}")
        for key, value in data.items():
            print(f"{Fore.MAGENTA}{key}:{Style.RESET_ALL} {value}")
        print(f"{Fore.CYAN}-------------------------------{Style.RESET_ALL}\n")

        # Prepare log entry based on the specified output format
        if output_format == 'txt':
            log_entry = (
                f"Timestamp: {data['Timestamp']}\n"
                f"IP Address: {data['IP Address']}\n"
                f"Hostname: {data['Hostname']}\n"
                f"ASN: {data['ASN']}\n"
                f"Organization: {data['Organization']}\n"
                f"Country: {data['Country']}\n"
                f"City: {data['City']}\n"
                f"Latitude: {data['Latitude']}\n"
                f"Longitude: {data['Longitude']}\n"
                f"Time Zone: {data['Time Zone']}\n"
                f"Postal Code: {data['Postal Code']}\n"
                f"Subnet: {data['Subnet']}\n"
                f"Registrar: {data['Registrar']}\n"
                f"Creation Date: {data['Creation Date']}\n"
                f"Expiration Date: {data['Expiration Date']}\n"
                f"{'-'*40}\n"
            )
            log_filename = os.path.join(LOGS_DIR, f"{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            async with aiofiles.open(log_filename, 'a') as f:
                await f.write(log_entry)
                print(f"TXT log entry written for IP: {ip}")
        
        elif output_format == 'json':
            log_filename = os.path.join(LOGS_DIR, f"{ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            async with aiofiles.open(log_filename, 'w') as f:
                await f.write(json.dumps(data, indent=4))
                print(f"JSON log entry written for IP: {ip}")
        
        elif output_format == 'csv':
            log_filename = os.path.join(LOGS_DIR, 'results.csv')
            file_exists = os.path.isfile(log_filename)
            async with aiofiles.open(log_filename, 'a', newline='') as f:
                # Prepare CSV row format
                row = {k: str(v) for k, v in data.items()}
                row = {k: v.replace('"', '""') if isinstance(v, str) else v for k, v in row.items()}
                row_csv = ','.join([f'"{v}"' if ',' in v or '"' in v else v for v in row.values()]) + '\n'
                if not file_exists:
                    header = ','.join(data.keys()) + '\n'
                    await f.write(header)
                await f.write(row_csv)
                print(f"CSV log entry written for IP: {ip}")

        # Update statistics for valid IPs processed
        stats['valid_ips'] += 1
        print(f"Finished processing IP: {ip}")

# Main function to handle the overall flow and manage asynchronous tasks
async def main(ip_addresses, readers, output_format, max_concurrent, stats):
    semaphore = asyncio.Semaphore(max_concurrent)  # Limit the number of concurrent tasks
    tasks = []
    for ip in ip_addresses:
        print(f"Queueing IP for processing: {ip}")
        tasks.append(process_ip(ip, readers, output_format, semaphore, stats))
    await asyncio.gather(*tasks)

    # Display summary after all IPs have been processed
    print(f"{Fore.GREEN}===== Processing Summary ====={Style.RESET_ALL}")
    print(f"Total IPs Processed: {stats['total_ips']}")
    print(f"Valid IPs: {stats['valid_ips']}")
    print(f"WHOIS Information Retrieved: {stats['whois_info_count']}")
    print(f"{Fore.GREEN}=============================={Style.RESET_ALL}")

# Entry point of the script
if __name__ == "__main__":
    # Argument parser for command-line inputs
    parser = argparse.ArgumentParser(
        description="Asynchronously process IP addresses to retrieve comprehensive geographical and organizational information.",
        epilog="Example usage:\n  python lookup-ip.py -ip 8.8.8.8 1.1.1.1\n  python lookup-ip.py -f ip_list.txt --format json",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-ip', '--ip-address', nargs='+', help='One or more IP addresses to process')
    parser.add_argument('-f', '--file', type=str, help='Path to a file containing IP addresses (one per line)')
    parser.add_argument('-fmt', '--format', choices=['txt', 'json', 'csv'], default='txt', help='Output format for the results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--max-concurrent', type=int, default=100, help='Maximum number of concurrent tasks')

    args = parser.parse_args()

    # Set the logging level based on verbosity flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    input_ips = []  # List to store input IPs
    stats = {
        'total_ips': 0,
        'valid_ips': 0,
        'whois_info_count': 0
    }

    # Collect IPs from command-line arguments
    if args.ip_address:
        for ip in args.ip_address:
            if validate_ip(ip):
                input_ips.append(ip)
                print(f"Validated IP from command line: {ip}")
            else:
                logging.error(f"Invalid IP address format: {ip}")

    # Collect IPs from file if provided
    if args.file:
        if os.path.isfile(args.file):
            print(f"Reading IP addresses from file: {args.file}")
            with open(args.file, 'r') as file:
                file_ips = [line.strip() for line in file if validate_ip(line.strip())]
                input_ips.extend(file_ips)
                print(f"Validated IPs from file: {file_ips}")
        else:
            logging.error(f"File not found: {args.file}")

    # If no IPs provided via command line or file, prompt for interactive input
    if not input_ips:
        print(f"{Fore.BLUE}No IP addresses provided via command line or file.{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Please enter IP addresses separated by spaces (e.g., 8.8.8.8 1.1.1.1):{Style.RESET_ALL}")
        user_input = input("> ")
        entered_ips = user_input.strip().split()
        for ip in entered_ips:
            if validate_ip(ip):
                input_ips.append(ip)
                print(f"Validated IP from interactive input: {ip}")
            else:
                logging.error(f"Invalid IP address format: {ip}")

    # If no valid IPs provided, exit the script
    if not input_ips:
        logging.error("No valid IP addresses to process. Exiting.")
        sys.exit(1)

    # Initialize GeoIP readers for ASN, City, and Country databases
    readers = GeoIPReaders()

    try:
        # Run the main async function
        print("Starting IP processing...")
        asyncio.run(main(input_ips, readers, args.format, args.max_concurrent, stats))
    finally:
        # Ensure all readers are properly closed to free resources
        readers.close()
        print("All tasks completed and resources cleaned up.")
