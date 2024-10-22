# Email and IP Lookup Tool

This tool provides functionality for looking up information about email domains and IP addresses. It includes features such as traceroute, WHOIS lookup, geolocation, reverse DNS, port scanning, and HTTP header inspection.

## Prerequisites

Before you begin, ensure you have met the following requirements:
* You have a Python 3.7+ installation
* You have a MaxMind account for GeoIP2 databases
* You have `nmap` installed on your system for port scanning (optional)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/email-ip-lookup-tool.git
   cd email-ip-lookup-tool
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Download GeoIP2 databases:
   - Create an account at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
   - Download the following databases and place them in the `data/` directory:
     * GeoLite2-City.mmdb
     * GeoLite2-Country.mmdb
     * GeoLite2-ASN.mmdb

## Usage

### Email Lookup

To lookup information for an email domain:

```
python lookup-email.py -a example@domain.com
```

### IP Lookup

To lookup information for IP addresses:

```
python lookup-ip.py -ip 8.8.8.8 1.1.1.1
```

## Note

This tool uses various third-party services and databases. Ensure you comply with their terms of service and usage policies.

## License

[Include your license information here]
