# NetInsightKit

Hey there, cyber sleuths and net ninjas!

Welcome to **NetInsightKit**, your trusty sidekick for digging up all the dirt (the legal kind, of course) about email domains and IP addresses. Whether you're hunting down a traceroute, snooping WHOIS info, or just geolocating like a pro, this toolkit has you covered. Reverse DNS? Yep. Port scanning? You bet. And even peeking at HTTP headers—because who doesn't love a good look behind the curtain?

> **Note:** We're just getting warmed up here, so expect this bad boy to keep evolving with new tricks as we figure out more cool stuff to add. Keep your eyes peeled!

> **Important:** Currently, NetInsightKit has only been tested on Windows. Could it work on Linux or Mac? Maybe. Do we guarantee it? Absolutely not. Proceed with curiosity (and caution) if you're on a non-Windows system.

## Prerequisites

Before diving in, you'll need:

- A Windows operating system (if you want to avoid unnecessary headaches).
- Python 3.7+ installed (either the old-school Python way or via Anaconda/Miniconda—we're cool with both).
- A free MaxMind account for GeoIP2 databases (seriously, it's free, no sneaky charges).
- `nmap` installed for port scanning (optional, but let's face it, you want to be that cool).

## Installation

Alright, let's get this party started:

1. **Clone the repo:**

   ```bash
   git clone https://github.com/chrisgaglardi/NetInsightKit.git
   cd NetInsightKit
   ```

2. **Set up the environment:**

   *Option A: Using venv (standard Python way)*
   
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

   *Option B: Using conda (Anaconda/Miniconda, because you're fancy like that)*
   
   ```bash
   conda create --name netinsightkit python=3.9
   conda activate netinsightkit
   ```

3. **Install required packages:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Download GeoIP2 databases:**
   
   - Head to [MaxMind](https://www.maxmind.com/en/geolite2/signup) and make a free account (it's easy, and yes, still free).
   - Grab these bad boys and plop them into the `data/` directory:
     - GeoLite2-City.mmdb
     - GeoLite2-Country.mmdb
     - GeoLite2-ASN.mmdb

## Usage

### Email Lookup

Want to dig up some dirt on an email domain? Here's how:

```bash
python lookup-email.py -a example@domain.com
```

### IP Lookup

Or maybe you've got a juicy IP address to investigate? No problem:

```bash
python lookup-ip.py -ip 8.8.8.8 1.1.1.1
```

## A Quick Heads-Up

Just a reminder: This toolkit leans on a bunch of third-party services and databases. Be sure to play by their rules—nobody likes a TOS violator.

## Future Development

This project is a living, breathing thing, just like your Wi-Fi connection at 3 AM (hopefully). New features and tools may be added in the future based on emerging needs and use cases. Or, who knows, it might just get ignored and wither away like that plant you swore you'd take care of. Only time will tell!

## License

Licensed under the MIT License because freedom is awesome. Check the [LICENSE](LICENSE) file for the fine print.

---

And that's it! Thanks for joining the ride. Let's go get those traces, ports, and headers like the digital detectives we are. Stay curious, stay safe, and don't forget to have fun while you're at it!

