#!/bin/bash

aquatoneTimeout=50000
massiveTime=3600
excludeStatus=404,403,401,503

echo -e "\e[1m\e[1;31m\n==========================================="
echo -e "    _                                               _              _ 
            (_)_   _ _ __ _   _ ___ _ __ ___  ___ ___  _ __ | |_ ___   ___ | |
            | | | | | '__| | | / __| '__/ _ \/ __/ _ \| '_ \| __/ _ \ / _ \| |
            | | |_| | |  | |_| \__ \ | |  __/ (_| (_) | | | | || (_) | (_) | |
            |_|\__,_|_|   \__,_|___/_|  \___|\___\___/|_| |_|\__\___/ \___/|_|
                                                                                 "
echo -e "          \n   @𝖗𝖊𝖆𝖑𝖍𝖆𝖒𝖆𝖆/𝕾𝖈𝖔𝖗𝖕𝖎𝖔𝖓-𝕾𝖍𝖎𝖊𝖑𝖉                          "
echo -e "===========================================\n\n\e[0m"

sudo apt-get -y update

echo -e "\e[1m\e[1;35mInstalling programming languages\n\e[0m"
 
echo -e "\e[1;36mInstalling Python\n\e[0m"
sudo apt-get install -y python3-pip
sudo apt-get install -y python-pip
sudo apt-get install -y dnspython

echo -e "\e[1;36mInstalling GO\n\n\e[0m"
sudo apt install -y golang
export GOROOT=/usr/lib/go
export GOPATH=~/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

echo "export GOROOT=/usr/lib/go" >> ~/.bashrc
echo "export GOPATH=~/go" >> ~/.bashrc
echo "export PATH=$GOPATH/bin:$GOROOT/bin:$PATH" >> ~/.bashrc

source ~/.bashrc

echo -e "\e[1;36mInstalling Cargo\n\n\e[0m"
sudo apt install cargo

echo -e "\e[1;36mInstalling html2text\n\n\e[0m"
sudo apt install html2text

echo -e "\e[1m\e[1;35mInstalling repositories\n\e[0m"
cd $HOME
mkdir tools
cd tools

echo -e "\e[1;36mCloning ASNLookup\n\e[0m"
git clone https://github.com/yassineaboukir/Asnlookup
cd Asnlookup
pip3 install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning ssl-checker\n\e[0m"
git clone https://github.com/narbehaj/ssl-checker
cd ssl-checker
pip3 install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning CloudEnum\n\e[0m"
git clone https://github.com/initstring/cloud_enum
cd cloud_enum
pip3 install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning GitDorker\n\e[0m"
git clone https://github.com/obheda12/GitDorker
cd GitDorker
pip3 install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning RobotScraper\n\e[0m"
git clone https://github.com/robotshell/robotScraper.git

echo -e "\e[1;36mInstall Arjun\n\e[0m"
pip3 install arjun

echo -e "\e[1;36mCloning nuclei-templates\n\e[0m"
git clone https://github.com/projectdiscovery/nuclei-templates.git


echo -e "\e[1;36mCloning Corsy\n\e[0m"
git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install requests
cd ..	

echo -e "\e[1;36mCloning SecretFinder\n\e[0m"
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
pip install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning CMSeek\n\e[0m"
git clone https://github.com/Tuhinshubhra/CMSeeK
cd CMSeeK
pip3 install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning Findomain\n\e[0m"
git clone https://github.com/findomain/findomain.git
cd findomain
cargo build --release
sudo cp target/release/findomain /usr/bin/
cd ..

echo -e "\e[1;36mCloning anti-burl\n\e[0m"
git clone https://github.com/tomnomnom/hacks
cd hacks/anti-burl/
go build main.go
sudo mv main ~/go/bin/anti-burl
cd ..

echo -e "\e[1;36mCloning XSRFProbe\n\e[0m"
git clone https://github.com/s0md3v/Bolt
cd Bolt
pip3 install -r requirements.txt
cd ..

echo -e "\e[1;36mCloning Gf-Patterns\n\e[0m"
git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir ~/.gf
cp -r Gf-Patterns/* ~/.gf
cd ..
cd ..

	
echo -e "\e[1m\e[1;35mInstalling tools\n\e[0m"

echo -e "\e[1;36mInstalling WhatWeb\n\n\e[0m"
sudo apt-get install whatweb

echo -e "\e[1;36mInstalling TheHarvester\n\n\e[0m"
sudo apt-get install theharvester

echo -e "\e[1;36mInstalling Nmap\n\n\e[0m"
sudo apt-get install nmap

echo -e "\e[1;36mInstalling Dirsearch\n\n\e[0m"
sudo apt-get install dirsearch

echo -e "\e[1;36mInstalling SqlMap\n\n\e[0m"
sudo apt-get install sqlmap 

echo -e "\e[1;36mInstalling Amass\n\e[0m"
go get -v github.com/OWASP/Amass/v3/..
sudo cp ~/go/bin/amass /usr/local/bin 

echo -e "\e[1;36mInstalling Aquatone\n\e[0m"
go get -u github.com/michenriksen/aquatone
sudo cp ~/go/bin/aquatone /usr/local/bin 

echo -e "\e[1;36mInstalling Subfinder\n\e[0m"
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
sudo cp ~/go/bin/subfinder /usr/local/bin 

echo -e "\e[1;36mInstalling Hakrawler\n\e[0m"
go install github.com/hakluke/hakrawler@latest
sudo cp ~/go/bin/hakrawler /usr/local/bin 

echo -e "\e[1;36mInstalling anew\n\e[0m"
go get -u github.com/tomnomnom/anew
sudo cp ~/go/bin/anew /usr/local/bin 

echo -e "\e[1;36mInstalling HTTPX\n\e[0m"
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
sudo cp ~/go/bin/httpx /usr/local/bin

echo -e "\e[1;36mInstalling Notify\n\e[0m"
GO111MODULE=on go get -v github.com/projectdiscovery/notify/cmd/notify
sudo cp ~/go/bin/notify /usr/local/bin

echo -e "\e[1;36mInstalling Nuclei\n\e[0m"
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
sudo cp ~/go/bin/nuclei /usr/local/bin

echo -e "\e[1;36mInstalling Shcheck\n\e[0m"
git clone https://github.com/santoru/shcheck

echo -e "\e[1;36mInstalling MailSpoof\n\e[0m"
sudo pip3 install mailspoof

echo -e "\e[1;36mInstalling MailSpoof\n\e[0m"
go get github.com/haccer/subjack
sudo cp ~/go/bin/subjack /usr/local/bin

echo -e "\e[1;36mInstalling gau\n\e[0m"
GO111MODULE=on go get -u -v github.com/lc/gau
sudo cp ~/go/bin/gau /usr/local/bin

echo -e "\e[1;36mInstalling gf\n\e[0m"
go get -u github.com/tomnomnom/gf
echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf
sudo cp ~/go/bin/gf /usr/local/bin

echo -e "\e[1;36mInstalling qsreplace\n\e[0m"
go get -u github.com/tomnomnom/qsreplace
sudo cp ~/go/bin/qsreplace /usr/local/bin

echo -e "\e[1;36mInstalling Dalfox\n\e[0m"
GO111MODULE=on go get -v github.com/hahwul/dalfox/v2
sudo cp ~/go/bin/dalfox /usr/local/bin

echo -e "\e[1;36mInstalling html-tool\n\e[0m"
go get -u github.com/tomnomnom/hacks/html-tool
sudo cp ~/go/bin/html-tool /usr/local/bin

echo -e "\e[1;36mInstalling waybackurls\n\e[0m"
go get github.com/tomnomnom/waybackurls
