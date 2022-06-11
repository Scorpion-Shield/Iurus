#!/bin/bash
#realhamaa

sed -i -e 's/\r$//' iurus.sh

aquatoneTimeout=50000
massiveTime=3600
excludeStatus=404,403,401,503

actualDir=$(pwd)

clear
clear
pwd
echo "Bash : ${BASH_VERSION}"

# passive Recon Function
passiveReconFunction(){
    echo -e "\e[1m\e[1;32m[*] Scan Started...\e[0m\n\n"
    echo -e "\e[1m\e[1;32m[*] Domain Name : \e[1;33m $domain \e[0m\n"
    ipaddress=$(dig +short $domain)
    echo -e "\e[1m\e[1;32m[*] IP Adress : \e[1;33m $ipaddress \e[0m\n\n"
    
    domain=$1
    domainName="https://"$domain
    company=$(echo -e $domain | awk -F[.] '{print $1}')
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir $domain
    
    cd $domain
    
    if [ -d footprinting ]; then rm -Rf footprinting; fi
    mkdir footprinting
    
    cd footprinting
    
    echo -e "\e[1;32m[+] Checking target is up or down...\e[0m\n"
    if ping -c 1 -W 1 "$domain" &> /dev/null;
    then
        echo -e "\n\e[1m\e[1;33m$domain\e[0m is up!\e[0m\n\n"
    else
        if [ $mode == "more" ]
        then
            echo -e "\n\e[1m\e[1;33m$domain\e[1;31m is not up.\e[0m\n\n"
            return
        else
            echo -e "\n\e[1m\e[1;33m$domain\e[1;31m is not up. Skipping passive reconnaissance\e[0m\n\n"
            exit 1
        fi
    fi
    
    echo -e "\e[1;32m[+] Whois Lookup\e[0m\n"
    echo -e "\e[0m\e[1;36mSearching domain name details, contact details of domain owner, domain name servers, netRange, domain dates, expiry records, records last updated...\e[0m\n\n"
    whois $domain | grep 'Domain\|Registry\|Registrar\|Updated\|Creation\|Registrant\|Name Server\|DNSSEC:\|Status\|Whois Server\|Admin\|Tech' | grep -v 'the Data in VeriSign Global Registry' | tee whois.txt
    
    echo -e "\n\e[1;32m[+] Nslookup \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching DNS Queries...\e[0m\n\n"
    nslookup $domain | tee nslookup.txt
    
    echo -e "\n\e[1;32m[+] Horizontal domain correlation/acquisitions \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching horizontal domains...\e[0m\n\n"
    email=$(whois $domain | grep "Registrant Email" | egrep -ho "[[:graph:]]+@[[:graph:]]+")
    curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" "https://viewdns.info/reversewhois/?q=$email" | html2text | grep -Po "[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" | tail -n +4  | head -n -1
    
    echo -e "\n\e[1;32m[+] ASN Lookup \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching ASN number of a company that owns the domain...\e[0m\n\n"
    python3 ~/tools/Asnlookup/asnlookup.py -o $company | tee -a asn.txt
    
    echo -e "\n\e[1;32m[+] WhatWeb \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching platform, type of script, google analytics, web server platform, IP address, country, server headers, cookies...\e[0m\n\n"
    whatweb $domain | tee whatweb.txt
    
    echo -e "\n\e[1;32m[+] SSL Checker \e[0m\n"
    echo -e "\e[0m\e[1;36mCollecting SSL/TLS information...\e[0m\n\n"
    python3 ~/tools/ssl-checker/ssl_checker.py -H $domainName | tee ssl.txt
    
    echo -e "\n\e[1;32m[+] Aquatone \e[0m\n"
    echo -e "\e[0m\e[1;36mTaking screenshot...\e[0m\n\n"
    echo -e $domainName | aquatone -screenshot-timeout $aquatoneTimeout -out screenshot &> /dev/null
    
    echo -e "\n\e[1;32m[+] TheHarvester \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching emails, subdomains, hosts, employee names...\e[0m\n\n"
    python3 ~/tools/theHarvester/theHarvester.py -d $domain -b all -l 500 -f theharvester.html > theharvester.txt
    echo -e "\e[0m\e[1;36mUsers found: \e[0m\n\n"
    cat theharvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | anew -q users.txt
    cat users.txt
    echo -e "\e[0m\e[1;36mIP's found: \e[0m\n\n"
    cat theharvester.txt | awk '/IPs/,/Emails/' | sed -e '1,2d' | head -n -2 | anew -q ips.txt
    cat ips.txt
    echo -e "\e[0m\e[1;36mEmails found: \e[0m\n\n"
    cat theharvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | anew -q emails.txt
    cat emails.txt
    echo -e "\e[0m\e[1;36mHosts found: \e[0m\n\n"
    cat theharvester.txt | awk '/Hosts/,/Trello/' | sed -e '1,2d' | head -n -2 | anew -q hosts.txt
    cat hosts.txt
    
    echo -e "\n\e[1;32m[+] CloudEnum \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching public resources in AWS, Azure, and Google Cloud....\e[0m\n\n"
    key=$(echo -e $domain | sed s/".com"//)
    python3 ~/tools/cloud_enum/cloud_enum.py -k $key --quickscan | tee cloud.txt
    
    echo -e "\n\e[1;32m[+] GitDorker \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching interesting data on GitHub...\e[0m\n\n"
    domainName="https://"$domain
    python3 ~/tools/GitDorker/GitDorker.py -t $github_token -d ~/tools/GitDorker/Dorks/alldorksv3 -q $domain -o dorks.txt
    
    if [ "$2" = true ];
    then
        echo -e "\n\e[1;32m[+] Whois results: \e[0m\n" | notify -silent | cat whois.txt | notify -silent
        echo -e "\n\e[1;32m[+] Nslookup results: \e[0m\n" | notify -silent | cat nslookup.txt | notify -silent
        echo -e "\n\e[1;32m[+] ASN Lookup results: \e[0m\n" | notify -silent | cat asn.txt | notify -silent
        echo -e "\n\e[1;32m[+] WhatWeb results: \e[0m\n" | notify -silent | cat whatweb.txt | notify -silent
        echo -e "\n\e[1;32m[+] SSL Checker results: \e[0m\n" | notify -silent | cat ssl.txt | notify -silent
        echo -e "\n\e[1;32m[+] TheHarvester users results: \e[0m\n" | notify -silent | cat users.txt | notify -silent
        echo -e "\n\e[1;32m[+] TheHarvester ips results: \e[0m\n" | notify -silent | cat ips.txt | notify -silent
        echo -e "\n\e[1;32m[+] TheHarvester emails results: \e[0m\n" | notify -silent | cat emails.txt | notify -silent
        echo -e "\n\e[1;32m[+] TheHarvester hosts results: \e[0m\n" | notify -silent | cat hosts.txt | notify -silent
        echo -e "\n\e[1;32m[+] CloudEnum results: \e[0m\n" | notify -silent | cat cloud.txt | notify -silent
        echo -e "\n\e[1;32m[+] GitDorker results: \e[0m\n" | notify -silent | cat dorks.txt | notify -silent
        
    fi
    
    cd $actualDir
}

# active Recon Function
activeReconFunction(){
    echo -e "\e[1m\e[1;32m[*] Starting scaning\e[0m\n\n"
    echo -e "\e[1m\e[1;32m[*] Domain Name : \e[1;33m $domain \e[0m\n"
    ipaddress=$(dig +short $domain)
    echo -e "\e[1m\e[1;32m[*] IP Adress : \e[1;33m $ipaddress \e[0m\n\n"
    
    domain=$1
    domainName="https://"$domain
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir $domain
    
    cd $domain
    
    if [ -d fingerprinting ]; then rm -Rf fingerprinting; fi
    mkdir fingerprinting
    
    cd fingerprinting
    
    echo -e "\n\e[1;32m[+] Robots.txt \e[0m\n"
    echo -e "\e[0m\e[1;36mChecking directories and files from robots.txt...\e[0m\n\n"
    python3 ~/tools/robotScraper/robotScraper.py -d $domain -s outputrobots.txt
    
    echo -e "\n\e[1;32m[+] Hakrawler & gau \e[0m\n"
    echo -e "\e[0m\e[1;36mGathering URLs and JavaSript file locations...\e[0m\n\n"
    echo -e $domainName | hakrawler | tee -a paths.txt
    gau $domain >> paths.txt
    sort -u paths.txt -o paths.txt
    
    echo -e "\n\e[1;32m[+] Arjun \e[0m\n"
    echo -e "\e[0m\e[1;36mFinding query parameters for URL endpoints....\e[0m\n\n"
    arjun -u $domainName -oT parameters.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: Secrets in JS\e[0m\n"
    echo -e "\e[0m\e[1;36mObtaining all the JavaScript files of the domain ...\e[0m\n\n"
    echo -e $domain | gau | grep '\.js$' | httpx -mc 200 -content-type -silent | grep 'application/javascript' | awk -F '[' '{print $1}' | tee -a js.txt
    echo -e "\n\e[0m\e[1;36mDiscovering sensitive data like apikeys, accesstoken, authorizations, jwt, etc in JavaScript files...\e[0m\n\n"
    for url in $(cat js.txt);do
        python3 ~/tools/SecretFinder/SecretFinder.py --input $url -o cli | tee -a secrefinder.txt
    done
    
    echo -e "\n\e[1;32m[+] DirSearch \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching interesting directories and files...\e[0m\n\n"
    sudo dirsearch -u $domain --deep-recursive --random-agent --exclude-status $excludeStatus -w $dictionary -o dirsearch
    
    echo -e "\n\e[1;32m[+] Nmap \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching open ports...\e[0m\n\n"
    nmap -p- --open -T5 -v -n $domain -oN nmap.txt
    
    if [ "$2" = true ];
    then
        echo -e "\n\e[1;32m[+] Robots.txt results: \e[0m\n" | notify -silent | cat outputrobots.txt | notify -silent
        echo -e "\n\e[1;32m[+] Hakrawler & gau results: \e[0m\n" | notify -silent | cat paths.txt | notify -silent
        echo -e "\n\e[1;32m[+] Arjun results: \e[0m\n" | notify -silent | cat parameters.txt | notify -silent
        echo -e "\n\e[1;32m[+] Secrets in JS results: \e[0m\n" | notify -silent | cat secrefinder.txt | notify -silent
        echo -e "\n\e[1;32m[+] Dirsearch results: \e[0m\n" | notify -silent | cat dirsearch | notify -silent
        echo -e "\n\e[1;32m[+] Nmap results: \e[0m\n" | notify -silent | cat nmap.txt | notify -silent
    fi
    
    cd $actualDir
}


all(){
    passiveReconFunction $domain
    activeReconFunction $domain
    vulnerabilities $domain
}


# Full Recon Function
fullReconFunction(){
    passiveReconFunction
    activeReconFunction
}

# Massive Recon Function
massiveReconFunction(){
    echo -e "\e[1m\e[1;32m[*] Starting massive vulnerability analysis\e[0m\n\n"
    echo -e "\e[1m\e[1;32m[*] Wildcard:\e[1;33m *.$wildcard \e[0m\n"
    
    if [ -d automatedRecon ];
    then
        rm -Rf automatedRecon;
    fi
    
    mkdir automatedRecon
    cd automatedRecon
    
    while true;
    do
        subfinder -d $wildcard | anew subdomains.txt | httpx | nuclei -t ~/tools/nuclei-templates/ | notify ; sleep $massiveTime;
        echo -e "\e[0m\e[1;36m[+] The vulnerabilities found have been notified. Waiting $massiveTime seconds for the new scan.\e[0m\n\n"
    done
    
    cd $actualDir
}


# Starting vulnerability scan
vulnerabilities(){
    echo -e "\e[1m\e[1;32m[*] Starting vulnerability scan\e[0m\n\n"
    echo -e "\e[1m\e[1;32m[*] Domain Name : \e[1;33m $domain \e[0m\n"
    ipaddress=$(dig +short $domain)
    echo -e "\e[1m\e[1;32m[*] IP Adress : \e[1;33m $ipaddress \e[0m\n\n"
    
    domain=$1
    domainName="https://"$domain
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir domain
    
    cd domain
    
    if [ -d vulnerabilities ]; then rm -Rf vulnerabilities; fi
    mkdir vulnerabilities
    
    cd vulnerabilities
    
    echo -e "\n\e[1;32m[+] Vulnerability: Missing headers\e[0m\n"
    echo -e "\e[0m\e[1;36mCheking security headers...\e[0m\n\n"
    python3 ~/tools/shcheck/shcheck.py $domainName | tee headers.txt | grep 'Missing security header:\|There are\|--'
    
    echo -e "\n\e[1;32m[+] Vulnerability: Email spoofing \e[0m\n"
    echo -e "\e[0m\e[1;36mCheking SPF and DMARC record...\e[0m\n\n"
    mailspoof -d $domain | tee spoof.json
    
    echo -e "\n\e[1;32m[+] Vulnerability: Subdomain takeover \e[0m\n"
    echo -e "\e[0m\e[1;36mChecking if sub-domain is pointing to a service that has been removed or deleted...\e[0m\n\n"
    subjack -d $domain -ssl -v | tee takeover.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: CORS\e[0m\n"
    echo -e "\e[0m\e[1;36mChecking all known misconfigurations in CORS implementations...\e[0m\n\n"
    python3 ~/tools/Corsy/corsy.py -u $domainName | tee cors.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: 403 bypass\e[0m\n"
    echo -e "\e[0m\e[1;36mGathering endpoints that they return 403 status code...\e[0m\n\n"
    touch endpoints403.txt
    saveUoutputFile=$actualDir"/targets/"$domain"/vulnerabilities/endpoints403.txt"
    sudo dirsearch -u $domainName --random-agent --include-status 403 -w $dictionary --format plain -o $saveUoutputFile
    echo -e "\n\e[0m\e[1;36mTrying to bypass 403 status code...\e[0m\n\n"
    for url in $(cat endpoints403.txt);
    do
        domainAWK=$domain":443"
        endpoint=$(echo -e $url | awk -F $domainAWK '{print $2}')
        if [ -n "$endpoint" ]
        then
            python3 ~/tools/403bypass/4xx.py $domainName $endpoint | tee -a bypass403.txt
        fi
    done
    
    echo -e "\n\e[1;32m[+] Vulnerability:  Cross Site Request Forgery (CSRF/XSRF)\e[0m\n"
    echo -e "\e[0m\e[1;36mChecking all known misconfigurations in CSRF/XSRF implementations...\e[0m\n\n"
    python3 ~/tools/Bolt/bolt.py -u $domainName -l 2 | tee -a csrf.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: Open Redirect\e[0m\n"
    echo -e "\e[0m\e[1;36mFinding Open redirect entry points in the domain...\e[0m\n\n"
    gau $domain | gf redirect archive | qsreplace | tee orURLs.txt
    echo -e "\n"
    echo -e "\e[0m\e[1;36mChecking if the entry points are vulnerable...\e[0m\n\n"
    cat orURLs.txt | qsreplace "https://google.com" | httpx -silent -status-code -location
    cat orURLs.txt | qsreplace "//google.com/" | httpx -silent -status-code -location
    cat orURLs.txt | qsreplace "//\google.com" | httpx -silent -status-code -location
    
    echo -e "\n\e[1;32m[+] Vulnerability: SSRF\e[0m\n"
    echo -e "\e[0m\e[1;36mTrying to find SSRF vulnerabilities...\e[0m\n\n"
    echo -e "\e[1;31m[!] Remember to enter your Burp Collaborator link in the configuration.cfg file \n\n\e[0m"
    findomain -t $domain | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace $burpCollaborator | tee -a ssrf.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: XSS\e[0m\n"
    echo -e "\e[0m\e[1;36mTrying to find XSS vulnerabilities...\e[0m\n\n"
    gau $domain | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe -o xss.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: SQLi\e[0m\n"
    echo -e "\e[0m\e[1;36mFinding SQLi entry points in the domain...\e[0m\n\n"
    gau $domain | gf sqli | tee sqlInjectionParameters.txt
    echo -e "\n"
    echo -e "\e[0m\e[1;36mChecking if the entry points are vulnerable...\e[0m\n\n"
    sqlmap -m sqlInjectionParameters.txt --batch --random-agent --level 1 | tee -a sqli.txt
    
    echo -e "\n\e[1;32m[+] Vulnerability: Multiples vulnerabilities\e[0m\n"
    echo -e "\e[0m\e[1;36mRunning multiple templates to discover vulnerabilities...\e[0m\n\n"
    nuclei -u $domain -t ~/tools/nuclei-templates/ -severity low,medium,high,critical -silent -o multipleVulnerabilities.txt
    
    if [ "$2" = true ];
    then
        echo -e "\n\e[1;32m[+] Missing headers results: \e[0m\n" | notify -silent | cat headers.txt | notify -silent
        echo -e "\n\e[1;32m[+] Email spoofing results: \e[0m\n" | notify -silent | cat spoof.json | notify -silent
        echo -e "\n\e[1;32m[+] Subdomain takeover results: \e[0m\n" | notify -silent | cat takeover.txt | notify -silent
        echo -e "\n\e[1;32m[+] CORS results: \e[0m\n" | notify -silent | cat cors.txt | notify -silent
        echo -e "\n\e[1;32m[+] 403 bypass results: \e[0m\n" | notify -silent | cat bypass403.txt | notify -silent
        echo -e "\n\e[1;32m[+] Cross Site Request Forgery (CSRF/XSRF) results: \e[0m\n" | notify -silent | cat csrf.txt | notify -silent
        echo -e "\n\e[1;32m[+] Open Redirect results: \e[0m\n" | notify -silent | cat orURLs.txt | notify -silent
        echo -e "\n\e[1;32m[+] SSRF results: \e[0m\n" | notify -silent | cat ssrf.txt | notify -silent
        echo -e "\n\e[1;32m[+] XSS results: \e[0m\n" | notify -silent | cat xss.txt | notify -silent
        echo -e "\n\e[1;32m[+] SQLi results: \e[0m\n" | notify -silent | cat sqli.txt | notify -silent
        echo -e "\n\e[1;32m[+] Nuclei results: \e[0m\n" | notify -silent | cat multipleVulnerabilities.txt | notify -silent
    fi
    
    cd $actualDir
}


# Wildcard Recon Function
wildcardReconFunction(){
    echo -e "\e[1m\e[1;31m[!] This mode does not accept any arguments\e[0m\n"
    echo -e "\e[1m\e[1;31m[!] A complete analysis will be carried out on all the subdomains found of the entered wildcard \e[0m\n\n"
    
    echo -e "\e[1m\e[1;32m[*] starting subdomain enumeration\e[0m\n\n"
    echo -e "\e[1m\e[1;32m[*] Wildcard:\e[1;33m *.$wildcard \e[0m\n"
    
    if [ -d subdomains ]; then rm -Rf subdomains; fi
    mkdir subdomains
    cd subdomains
    
    echo -e "\n\e[1;32m[+] Subfinder \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching subdomains...\e[0m\n\n"
    subfinder -silent -d $wildcard -o subdomains.txt
    
    echo -e "\n\e[1;32m[+] Amass \e[0m\n"
    echo -e "\e[0m\e[1;36mSearching subdomains with bruteforce...\e[0m\n\n"
    amass enum -d $wildcard -w $dnsDictionary -o bruteforce.txt
    cat bruteforce.txt >> subdomains.txt
    rm bruteforce.txt
    sort -u subdomains.txt -o subdomains.txt
    
    echo -e "\n\e[1;32m[+] Httpx \e[0m\n"
    echo -e "\e[0m\e[1;36mChecking up subdomains...\e[0m\n\n"
    httpx -l subdomains.txt -silent -o up.txt
    
    cp up.txt activesubdomain.txt
    sed -i 's#^http://##; s#/score/$##' activesubdomain.txt
    sed -i 's#^https://##; s#/score/$##' activesubdomain.txt
    sort -u activesubdomain.txt -o activesubdomain.txt
    
    cat activesubdomain.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > up.json
    cat subdomains.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > subdomains.json
    
    sed 's/ \+/,/g' activesubdomain.txt > up.csv
    sed 's/ \+/,/g' subdomains.txt > subdomains.csv
    
    mode="more"
    
    for domain in $(cat activesubdomain.txt);do
        all $domain $more
    done
    
    cd $actualDir
}

# Help Menu
help(){
    echo -e "\e[1m\e[1;32mUSAGE\e[0m\n"
    echo -e "$0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
    echo -e "           	      [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h] \n\n"
    echo -e "\e[1m\e[1;32mTARGET OPTIONS\e[0m"
    echo -e "   -d domain.com     Target domain"
    echo -e "   -w domain.com     Wildcard domain"
    echo -e "   -l list.txt       Target list"
    echo -e " \n"
    echo -e "\e[1m\e[1;32mMODE OPTIONS\e[0m"
    echo -e "   -a, --all                 All mode - Full scan."
    echo -e "   -p, --passive             Passive reconnaissance."
    echo -e "   -x, --active              Active reconnaissance."
    echo -e "   -m, --massive             Massive recon."
    echo -e "   -r, --recon               Active and passive reconnaissance."
    echo -e "   -v, --vulnerabilities     Check Vulnerabilities only."
    echo -e "   -h, --help                Help - Show help menu"
    
}


usage(){
    echo -e "\n"
    echo -e "Usage: $0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
    echo -e "\n           	      [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h] \n\n"
    exit 2
}

# Print Banner
echo -e "\e[1m\e[1;31m"
echo -e "\e[1m
────────────────────────────────────────────────────────────────────────────
─██████████─██████──██████─████████████████───██████──██████─██████████████─
─██░░░░░░██─██░░██──██░░██─██░░░░░░░░░░░░██───██░░██──██░░██─██░░░░░░░░░░██─
─████░░████─██░░██──██░░██─██░░████████░░██───██░░██──██░░██─██░░██████████─
───██░░██───██░░██──██░░██─██░░██────██░░██───██░░██──██░░██─██░░██─────────
───██░░██───██░░██──██░░██─██░░████████░░██───██░░██──██░░██─██░░██████████─
───██░░██───██░░██──██░░██─██░░░░░░░░░░░░██───██░░██──██░░██─██░░░░░░░░░░██─
───██░░██───██░░██──██░░██─██░░██████░░████───██░░██──██░░██─██████████░░██─
───██░░██───██░░██──██░░██─██░░██──██░░██─────██░░██──██░░██─────────██░░██─
─████░░████─██░░██████░░██─██░░██──██░░██████─██░░██████░░██─██████████░░██─
─██░░░░░░██─██░░░░░░░░░░██─██░░██──██░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─
─██████████─██████████████─██████──██████████─██████████████─██████████████─
──────────────────────────────────────────────────────────────────────────── \e[0m"

echo -e "\e[1m\e[1;35m\e[1;31m\n\t\@𝖗𝖊𝖆𝖑𝖍𝖆𝖒𝖆𝖆/𝕾𝖈𝖔𝖗𝖕𝖎𝖔𝖓-𝕾𝖍𝖎𝖊𝖑𝖉 \n\e[0m"

parsedArguments=$(getopt -a -n iurus -o "d:w:l:apxrvmnh" --long "domain:,wildcard:,list:,all,passive,active,recon,vulnerabilities,massive,notify,help" -- "$@")
validArguments=$?

if [ $validArguments != "0" ];
then
    usage
fi

if [ $# == 0 ]
then
    echo -e "\e[1;31m [!] No arguments detected. \n\e[0m"
    exit 1
fi

eval set -- "$parsedArguments"

modrecon=0
vulnerabilitiesMode=false
notifyMode=false

while :
do
    case "$1" in
        '-d' | '--domain')
            domain=$2
            shift
            shift
            continue
        ;;
        '-w' | '--wildcard')
            wildcard=$2
            shift
            shift
            continue
        ;;
        '-l' | '--list')
            domainList=$2
            shift
            shift
            continue
        ;;
        '-a' | '--all')
            modrecon=1
            shift
            continue
        ;;
        '-p' | '--passive')
            modrecon=2
            shift
            continue
        ;;
        '-x' | '--active')
            modrecon=3
            shift
            continue
        ;;
        '-r' | '--recon')
            modrecon=4
            shift
            continue
        ;;
        '-v' | '--vulnerabilities')
            vulnerabilitiesMode=true
            shift
            continue
        ;;
        '-m' | '--massive')
            modrecon=5
            shift
            continue
        ;;
        '-n' | '--notify')
            notifyMode=true
            shift
            continue
        ;;
        '-h' | '--help')
            help
            exit
        ;;
        '--')
            shift
            break
        ;;
        *)
            echo -e "\e[1;31m[!] Unexpected option: $1 - this should not happen. \n\e[0m"
            usage
        ;;
    esac
done

if [ -z "$domain" ] && [ -z "$wildcard" ] && [ -z "$domainList" ]
then
    echo -e "\e[1;31m[!] Please specify a domain (-d | --domain), a wildcard (-w | --wildcard) or a list of domains(-l | --list) \n\e[0m"
    exit 1
fi

if [ ! -d targets ];
then
    mkdir targets
fi

if [ ! -z "$wildcard" ] && [ $modrecon != 5 ]
then
    wildcardReconFunction $wildcard
    exit 1
fi

case $modrecon in
    0)
        if [ -z "$domainList" ]
        then
            if [ $vulnerabilitiesMode == true ]
            then
                vulnerabilities $domain $notifyMode
            fi
        else
            if [ $vulnerabilitiesMode == true ]
            then
                for domain in $(cat $domainList);do
                    vulnerabilities $domain $notifyMode
                done
            fi
        fi
    ;;
    1)
        if [ -z "$domainList" ]
        then
            all $domain $notifyMode
        else
            for domain in $(cat $domainList);do
                all $domain $notifyMode
            done
        fi
    ;;
    2)
        if [ -z "$domainList" ]
        then
            passiveReconFunction $domain $notifyMode $vulnerabilitiesMode
        else
            for domain in $(cat $domainList);do
                passiveReconFunction $domain $notifyMode $vulnerabilitiesMode
            done
        fi
    ;;
    3)
        if [ -z "$domainList" ]
        then
            activeReconFunction $domain $notifyMode $vulnerabilitiesMode
        else
            for domain in $(cat $domainList);do
                activeReconFunction $domain $notifyMode $vulnerabilitiesMode
            done
        fi
    ;;
    4)
        if [ -z "$domainList" ]
        then
            fullReconFunction $domain $notifyMode
        else
            for domain in $(cat $domainList);do
                fullReconFunction $domain $notifyMode
            done
        fi
    ;;
    5)
        if [ ! -z "$wildcard"  ]
        then
            massiveReconFunction $wildcard
        else
            echo -e "\e[1;31m[!] This mode only works with a wildcard (-w | --wildcard) \n\e[0m"
            exit 1
        fi
    ;;
    *)
        help
        exit 1
    ;;
esac