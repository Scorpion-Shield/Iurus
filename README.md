### Iurus is a Multifunctional Web Recon & Vulnerability Scanner Tool and incredibly fast crawler that can find multiple vulnerabilitIES and gather information.


### Check for vulnerabilities

- Reflected XSS
- Multi-threaded crawling
- Open-redirection
- Subdomain Takeover
- SQL Injection
- HTML INjection
- SSRF
- CSRF
- CORS
- Find vulnerable JS library
- Information disclosure

### Check for Information in recon

- Web IP Address
- Server IP Address
- Cname Recods
- DNS lookup
- SPF lookup
- Hidden IP
- API Endpoints
- JS endpoints
- XSS Endpoints
- directory Search
- Subdomain Enumeration

--------------------------------

### Installation

git clone https://github.com/Scorpion-Shield/Iurus

cd Iurus

chmod +x install.sh iurus.sh

sed -i -e 's/\r$//' install.sh iurus.sh 


./install.sh

-------------------------------

### Usage

./iurus.sh -h

-------------------------------

### Example

./iurus.sh -d target.com -a {Full Scan}

./iurus.sh -d target.com -p {Passive reconnaissance}

./iurus.sh -d target.com -a {Active reconnaissance}

./iurus.sh -d target.com -m {Massive recon}

./iuruw.sh -d target.com -r {Active and passive reconnaissance}

./iurus.sh -d target.com -v {Check Vulnerabilities only}

--------------------------------
