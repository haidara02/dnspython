# dnspython
This program measures the DNS resolution time for any valid DNS resolvers.

- **Number of Queries**: 5000 resolvable queries per resolver.
- **Sample Query Source**: Domain lists from OpenDNS's public domain list:  
  [OpenDNS Random Domains](https://github.com/opendns/public-domain-lists/blob/master/opendns-random-domains.txt#L1012)

## Getting Started
1. **If using the custom resolver, `resolver.py`**, start the resolver script.
```bash
   $ python3 resolver.py port [+enhanced args]
```
2. In the `performance.sh` script:
   - Ensure the `-rd` flag is enabled for public DNS testing.
   - Otherwise, leave the script as is.
3. Run the `performance.sh` script and enter resolver IP and port number.
Example with Google DNS:
If testing with Google DNS (IP: 8.8.8.8, Port: 53), provide the following inputs when prompted:
```bash
Enter resolver IP: 8.8.8.8
Enter port number: 5300
```
5. The shell script will generate three output files per resolver:
   - `[resolver_ip]_raw.txt`: Contains raw numerical data.
   - `[resolver_ip]_data.csv`: Contains domain names and resolution times.
   - `[resolver_ip]_response.txt`: Parsed output with detailed resolver responses.
