#!/usr/bin/env bash

# Colors
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'

if [[ -d $HOME/tools ]]; then
  echo "$GREEN""[+]Tools Directory is already made.""$NC"
else
  mkdir $HOME/tools
fi

if [[ -d $HOME/tools/lists ]]; then
  echo "$GREEN""[+]Wordlists Directory is already made.""$NC"
else
  mkdir $HOME/tools/lists
fi

TOOLS="$HOME/tools"

install_go() {
  if [[ -e /usr/local/go/bin/go ]]; then
    echo "$GREEN""[i] Go is already installed, skipping installation.""$NC"
    return
  fi
  echo -e "$GREEN""[+] Installing go 1.14.6.""$NC"
  wget https://golang.org/dl/go1.14.6.linux-amd64.tar.gz
  #check if sudo if not cue for password
  sudo tar -C /usr/local -xzf go1.14.6.linux-amd64.tar.gz
  echo "export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin" >> $HOME/.profile
  echo "export GO111MODULE=on" >> $HOME/.profile
  echo "export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin" >> $HOME/.bashrc
  echo "export GO111MODULE=on" >> $HOME/.bashrc
  source $HOME/.bashrc
  source $HOME/.profile
  rm -f go1.14.6.linux-amd64.tar.gz
}

install_go_tools() {
  echo -e "$GREEN""[+] Installing hakluke hacks.""$NC"
  go get -u github.com/hakluke/hacks
  echo -e "$GREEN""[+] Installing unfurl.""$NC"
  go get -u github.com/tomnomnom/unfurl
  echo -e "$GREEN""[+] Installing qsreplace.""$NC"
  go get -u github.com/tomnomnom/qsreplace
  echo -e "$GREEN""[+] Installing dnsgrep.""$NC"
  go get -u github.com/tomnomnom/dnsgrep
  echo -e "$GREEN""[+] Installing anew.""$NC"
  go get -u github.com/tomnomnom/anew
  echo -e "$GREEN""[+] Installing meg.""$NC"
  go get -u github.com/tomnomnom/meg
  echo -e "$GREEN""[+] Installing gf.""$NC"
  go get -u github.com/tomnomnom/gf
  git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/Gf-Patterns
  mkdir $HOME/.gf
  mv $HOME/Gf-Patterns/*.json $HOME/.gf
  rm -fr $HOME/Gf-Patterns
  echo -e "$GREEN""[+] Installing githound.""$NC"
  go get -u github.com/tillson/git-hound
  echo -e "$GREEN""[+] Installing hakrevdns.""$NC"
  go get -u github.com/hakluke/hakrevdns
  echo -e "$GREEN""[+] Installing hakcrawler.""$NC"
  go get -u github.com/hakluke/hakrawler
  echo -e "$GREEN""[+] Installing hakcheckurl.""$NC"
  go get -u github.com/hakluke/hakcheckurl
  echo -e "$GREEN""[+] Installing haksecuritytxt.""$NC"
  go get -u github.com/hakluke/haksecuritytxt
  echo -e "$GREEN""[+] Installing haktldextract.""$NC"
  go get -u github.com/hakluke/haktldextract
  echo -e "$GREEN""[+] Installing webanalyze.""$NC"
  go get -u github.com/rverton/webanalyze/...
  echo -e "$GREEN""[+] Installing shuffledns.""$NC"
  go get -u github.com/projectdiscovery/shuffledns/cmd/shuffledns
  echo -e "$GREEN""[+] Installing shhgit.""$NC"
  go get -u github.com/eth0izzle/shhgit
  echo -e "$GREEN""[+] Installing redAsset.""$NC"
  go get -u github.com/rverton/redAsset
  echo -e "$GREEN""[+] Installing naabu.""$NC"
  go get -u github.com/projectdiscovery/naabu/cmd/naabu
  echo -e "$GREEN""[+] Installing inscope.""$NC"
  go get -u github.com/tomnomnom/hacks/inscope
  echo -e "$GREEN""[+] Installing httpx.""$NC"hacks
  go get -u github.com/projectdiscovery/httpx/cmd/httpx
  echo -e "$GREEN""[+] Installing hakcheckurl.""$NC"
  go get -u github.com/hakluke/hakcheckurl
  echo -e "$GREEN""[+] Installing gitrob.""$NC"
  go get -u github.com/michenriksen/gitrob
  echo -e "$GREEN""[+] Installing subjs.""$NC"
  go get -u github.com/lc/subjs
  echo -e "$GREEN""[+] Installing getjs.""$NC"
  go get -u github.com/003random/getJS
  echo -e "$GREEN""[+] Installing dalfox.""$NC"
  go get -u github.com/hahwul/dalfox
  echo -e "$GREEN""[+] Installing commonspeak2.""$NC"
  go get -u github.com/assetnote/commonspeak2
  echo -e "$GREEN""[+] Installing tomnomnom hacks.""$NC"
  go get -u github.com/tomnomnom/hacks
  echo -e "$GREEN""[+] Installing amass.""$NC"
  go get -u github.com/OWASP/Amass/v3/...
  echo -e "$GREEN""[+] Installing gau.""$NC"
  go get -u github.com/lc/gau
  echo -e "$GREEN""[+] Installing subfinder.""$NC"
  go get -u github.com/projectdiscovery/subfinder/cmd/subfinder
  echo -e "$GREEN""[+] Installing subjack.""$NC"
  go get -u github.com/haccer/subjack
  echo -e "$GREEN""[+] Installing ffuf.""$NC"
  go get -u github.com/ffuf/ffuf
  echo -e "$GREEN""[+] Installing gobuster.""$NC"
  go get -u github.com/OJ/gobuster
  echo -e "$GREEN""[+] Installing inception.""$NC"
  go get -u github.com/proabiral/inception
  echo -e  "$GREEN""[+] Installing waybackurls.""$NC"
  go get -u github.com/tomnomnom/waybackurls
  echo -e "$GREEN""[+] Installing goaltdns.""$NC"
  go get -u github.com/subfinder/goaltdns
  echo -e "$GREEN""[+] Installing rescope.""$NC"
  go get -u github.com/root4loot/rescope
  echo -e "$GREEN""[+] Installing httprobe.""$NC"
  go get -u github.com/tomnomnom/httprobe
  echo -e "$GREEN""[+] Installing gowitness.""$NC"
  go get -u github.com/anshumanbh/gowitness
  echo -e "$GREEN""[+] Installing aquatone.""$NC"
  go get -u github.com/michenriksen/aquatone
  echo -e "$GREEN""[+] Installing Aron.""$NC"
  go get -u github.com/m4ll0k/Aron
  echo -e "$GREEN""[+] Installing 1ndiList.""$NC"
  go get -u github.com/1ndianl33t/1ndiList
  echo -e "$GREEN""[+] Installing cf-check.""$NC"
  go get -u github.com/dwisiswant0/cf-check
  echo -e "$GREEN""[+] Installing ohmybackup.""$NC"
  go get -u github.com/1ndianl33t/ohmybackup
  echo -e "$GREEN""[+] Installing Golinkfinder.""$NC"
  go get -u github.com/1ndianl33t/GoLinkFinder
  echo -e "$GREEN""[+] Installing csp.""$NC"
  go get -u github.com/edoverflow/csp
  echo -e "$GREEN""[+] Installing tomnomnom hacks.""$NC"
  go get -u github.com/tomnomnom/hacks
  echo -e "$GREEN""[+] Installing whoareyou.""$NC"
  go get -u github.com/ameenmaali/whoareyou
  echo -e "$GREEN""[+] Installing wordlistgen.""$NC"
  go get -u github.com/ameenmaali/wordlistgen
  echo -e "$GREEN""[+] Installing nuclei.""$NC"
  go get -u github.com/projectdiscovery/nuclei/v2/cmd/nuclei
  echo -e "$GREEN""[+] Installing/Updateing nuclei templates.""$NC"
  nuclei -update-templates -update-directory $TOOLS
  echo -e "$GREEN""[+] Installing metabigor.""$NC"
  go get -u github.com/j3ssie/metabigor
  echo -e "$GREEN""[+] Installing shosubgo.""$NC"
  go get -u github.com/incogbyte/shosubgo
  echo -e "$GREEN""[+] Installing goaltdns.""$NC"
  go get -u github.com/subfinder/goaltdns
  echo -e "$GREEN""[+] Installing gospider.""$NC"
  go get -u github.com/theblackturtle/gospider
  echo -e "$GREEN""[+] Installing andor.""$NC"
  go get -u github.com/sadicann/andor
  echo -e "$GREEN""[+] Installing mass3.""$NC"
  go get -u github.com/smiegles/mass3
  echo -e "$GREEN""[+] Installing assetfinder.""$NC"
  go get -u github.com/tomnomnom/assetfinder
  echo -e "$GREEN""[+] Installing urinteresting.""$NC"
  go get -u github.com/tomnomnom/hacks/urinteresting
  echo -e "$GREEN""[+] Installing kxss.""$NC"
  go get -u github.com/Emoe/kxss
  echo -e "$GREEN""[+] Installing qsreplace.""$NC"
  go get -u github.com/tomnomnom/qsreplace
  echo -e "$GREEN""[+] Installing qsinject.""$NC"
  go get -u github.com/ameenmaali/qsinject
  echo -e "$GREEN""[+] Installing qsfuzz.""$NC"
  go get -u github.com/ameenmaali/qsfuzz

  go get -u github.com/x1sec/commit-stream
}

install_eyewitness(){
  if [[ -d $TOOLS/EyeWitness ]]; then
    echo -e "$GREEN""[+] Updating eyewitness.""$NC"
    cd $TOOLS/EyeWitness
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing eyewitness.""$NC"
    git clone https://github.com/FortyNorthSecurity/EyeWitness $TOOLS/EyeWitness
  fi
}

install_openredirex(){
  if [[ -d $TOOLS/OpenRedireX ]]; then
    echo -e "$GREEN""[+] Updating openredirex.""$NC"
    cd $TOOLS/OpenRedireX
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing openredirex.""$NC"
    git clone https://github.com/devanshbatham/OpenRedireX $TOOLS/OpenRedireX
  fi
}

install_archievefuzz(){
  if [[ -d $TOOLS/ArchiveFuzz ]]; then
    echo -e "$GREEN""[+] Updating archivefuzz.""$NC"
    cd $TOOLS/ArchiveFuzz
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing archivefuzz.""$NC"
    git clone https://github.com/devanshbatham/ArchiveFuzz $TOOLS/ArchiveFuzz
    python3 -m pip install -r $TOOLS/ArchiveFuzz/requirements.txt
  fi
}

install_passivehunter(){
  if [[ -d $TOOLS/Passivehunter ]]; then
    echo -e "$GREEN""[+] Updating passivehunter.""$NC"
    cd $TOOLS/Passivehunter
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing passivehunter.""$NC"
    git clone https://github.com/devanshbatham/Passivehunter $TOOLS/Passivehunter
    python3 -m pip install -r $TOOLS/Passivehunter/requirements.txt
  fi
}

install_theharvester(){
  if [[ -d $TOOLS/theHarvester ]]; then
    echo -e "$GREEN""[+] Updating theharvester.""$NC"
    cd $TOOLS/theHarvester
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing theharvester.""$NC"
    git clone https://github.com/laramies/theHarvester $TOOLS/theHarvester
    python3 -m pip install -r $TOOLS/theHarvester/requirements/dev.txt
    python3 -m pip install -r $TOOLS/theHarvester/requirements/base.txt
  fi
}

install_linkfinder(){
  if [[ -d $TOOLS/LinkFinder ]]; then
    echo -e "$GREEN""[+] Updating linkfinder.""$NC"
    cd $TOOLS/LinkFinder
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing linkfinder.""$NC"
    git clone https://github.com/GerbenJavado/LinkFinder.git $TOOLS/LinkFinder
    python3 -m pip install -r $TOOLS/LinkFinder/requirements.txt
  fi
}

install_rue(){
  if [[ -d $TOOLS/relative-url-extractor ]]; then
    echo -e "$GREEN""[+] Updating relative url extractor.""$NC"
    cd $TOOLS/relative-url-extractor
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing relative url extractor.""$NC"
    git clone https://github.com/jobertabma/relative-url-extractor $TOOLS/relative-url-extractor
  fi
}

install_waybackrobots(){
  if [[ -f $TOOLS/waybackrobots.py ]]; then
    echo -e "$GREEN""[+] waybackrobots is already installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing waybackrobots.""$NC"
    wget https://gist.githubusercontent.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07/raw/5dd007667a5b5400521761df931098220c387551/waybackrobots.py -O $TOOLS/waybackrobots.py
  fi
}

install_sqlmap(){
  if [[ -d $TOOLS/sqlmap-dev ]]; then
    echo -e "$GREEN""[+] Updating sqlmap.""$NC"
    cd $TOOLS/sqlmap-dev
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing sqlmap.""$NC"
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $TOOLS/sqlmap-dev
  fi
}

install_identywaf(){
  if [[ -d $TOOLS/identYwaf ]]; then
    echo -e "$GREEN""[+] Updating identYwaf.""$NC"
    cd $TOOLS/identYwaf
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing identYwaf.""$NC"
    git clone https://github.com/stamparm/identYwaf $TOOLS/identYwaf
  fi
}

install_dnsvalidator(){
  if [[ -d $TOOLS/dnsvalidator ]]; then
    echo -e "$GREEN""[+] Updating dnsvalidator.""$NC"
    cd $TOOLS/dnsvalidator
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing dnsvalidator.""$NC"
    git clone https://github.com/vortexau/dnsvalidator $TOOLS/dnsvalidator
    python3 -m pip install -r $TOOLS/dnsvalidator/requirements.txt
  fi
}

install_xsstrike(){
  if [[ -d $TOOLS/XSStrike ]]; then
    echo -e "$GREEN""[+] Updating xsstrike.""$NC"
    cd $TOOLS/XSStrike
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing xsstrike.""$NC"
    git clone https://github.com/s0md3v/XSStrike $TOOLS/XSStrike
    python3 -m pip install -r $TOOLS/XSStrike/requirements.txt
  fi
}

install_arjun(){
  if [[ -d $TOOLS/Arjun ]]; then
    echo -e "$GREEN""[+] Updating arjun.""$NC"
    cd $TOOLS/Arjun
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing arjun.""$NC"
    git clone https://github.com/s0md3v/Arjun $TOOLS/Arjun
  fi
}

install_cmseek(){
  if [[ -d $TOOLS/CMSeek ]]; then
    echo -e "$GREEN""[+] Updating cmseek.""$NC"
    cd $TOOLS/CMSeek
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing cmseek.""$NC"
    git clone https://github.com/Tuhinshubhra/CMSeek $TOOLS/CMSeek
    python3 -m pip install -r $TOOLS/CMSeek/requirements.txt
  fi
}

install_xsrfprobe(){
  echo -e "$GREEN""[+] Installing xsrfprobe.""$NC"
  python3 -m pip install xsrfprobe
}

install_corsy(){
  if [[ -d $TOOLS/Corsy ]]; then
    echo -e "$GREEN""[+] Updating corsy.""$NC"
    cd $TOOLS/Corsy
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing corsy.""$NC"
    git clone https://github.com/s0md3v/Corsy $TOOLS/Corsy
    python3 -m pip install -r $TOOLS/Corsy/requirements.txt
  fi
}

install_tplmap(){
  if [[ -d $TOOLS/tplmap ]]; then
    echo -e "$GREEN""[+] Updating tplmap.""$NC"
    cd $TOOLS/tplmap
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing tplmap.""$NC"
    git clone https://github.com/epinna/tplmap $TOOLS/tplmap
    python3 -m pip install -r $TOOLS/tplmap/requirements.txt
  fi
}

# check if install if so update wpscan --update
install_wpscan(){
  echo -e "$GREEN""[+] Installing wpscan.""$NC"
  sudo gem install wpscan
}

install_crlftest(){
  if [[ -d $TOOLS/CRLF-Injection-Scanner ]]; then
    echo -e "$GREEN""[+] Updating crlftest.""$NC"
    cd $TOOLS/CRLF-Injection-Scanner
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing crlftest.""$NC"
    git clone https://github.com/streaak/CRLF-Injection-Scanner $TOOLS/CRLF-Injection-Scanner
  fi
}

install_masscan(){
  if [[ -d $TOOLS/masscan ]]; then
    echo -e "$GREEN""[+] Updating massdns.""$NC"
    cd $TOOLS/masscan
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing massdns.""$NC"
    git clone https://github.com/robertdavidgraham/masscan $TOOLS/masscan
  fi
  #Compile it
  echo -e "$GREEN""[+] Compiling masscan from source.""$NC"
  cd $TOOLS/masscan
  make -j
  cd -
}

install_corstest() {
  if [[ -d $TOOLS/CORStest ]]; then
    echo -e "$GREEN""[+] Updating CORStest.""$NC"
    cd $TOOLS/CORStest
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing CORStest.""$NC"
    git clone https://github.com/RUB-NDS/CORStest.git $TOOLS/CORStest
  fi
}

install_s3scanner() {
  if [[ -d $TOOLS/S3Scanner ]]; then
    echo -e "$GREEN""[+] Updating S3Scanner.""$NC"
    cd $TOOLS/S3Scanner
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing S3Scanner.""$NC"
    git clone https://github.com/sa7mon/S3Scanner.git $TOOLS/S3Scanner
    python3 -m pip install -r $TOOLS/S3Scanner/requirements.txt
  fi
}

install_massdns() {
  if [[ -d $TOOLS/massdns ]]; then
    echo -e "$GREEN""[+] Updating massdns.""$NC"
    cd $TOOLS/massdns
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing massdns.""$NC"
    git clone https://github.com/blechschmidt/massdns.git $TOOLS/massdns
  fi
  # Compile it
  echo -e "$GREEN""[+] Compiling massdns from source.""$NC"
  cd $TOOLS/massdns
  make -j
  cd -
}

install_metasploit(){
  if [[ -d $TOOLS/metasploit-framework ]]; then
    echo -e "$GREEN""[+] Metasploit is already installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing metasploit-framework.""$NC"
    git clone https://github.com/rapid7/metasploit-framework $TOOLS/metasploit-framework
  fi
}

install_pastebin_scraper() {
  if [[ -d $TOOLS/pastebin-scraper ]]; then
    echo -e "$GREEN""[+] Updating pastebinscraper.""$NC"
    cd $TOOLS/pastebin-scraper
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing pastebinscraper.""$NC"
    git clone https://github.com/streaak/pastebin-scraper.git $TOOLS/pastebin-scraper
  fi
}

install_waybacksqliscanner() {
  if [[ -d $TOOLS/sqliscanner.py ]]; then
    echo -e "$GREEN""[+] Already have sqliscanner installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing sqliscanner.""$NC"
    wget https://raw.githubusercontent.com/ghostlulzhacks/waybackSqliScanner/master/sqliscanner.py
  fi
}

install_smuggler() {
  if [[ -d $TOOLS/smuggler ]]; then
    echo -e "$GREEN""[+] Already have smuggler installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing smuggler.""$NC"
    git clone https://github.com/defparam/smuggler.git $TOOLS/smuggler
  fi
}

install_ssrf() {
  if [[ -f $TOOLS/ssrf.py ]]; then
    echo -e "$GREEN""[+] Already have ssrf.py installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing ssrf.py.""$NC"
    cd $TOOLS
    wget https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/ssrf.py 
    cd - 
  fi
}

install_getjswords() {
  if [[ -f $TOOLS/getjswords.py ]]; then
    echo -e "$GREEN""[+] Already have getjswords.py installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing getjswords.py.""$NC"
    cd $TOOLS
    wget https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py
    cd -
  fi
}

install_getrelations() {
  if [[ -f $TOOLS/getrelationship.py ]]; then
    echo -e "$GREEN""[+] Already have getrelationship.py installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing getrelationship.py.""$NC"
    cd $TOOLS
    wget https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getrelationship.py
    cd -
  fi
}

install_atlas() {
  if [[ -d $TOOLS/Atlas ]]; then
    echo -e "$GREEN""[+] Updating Atlas.""$NC"
    cd $TOOLS/Atlas
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing Atlas.""$NC"
    git clone https://github.com/m4ll0k/Atlas.git $TOOLS/Atlas
  fi
}

install_awsgen() {
  if [[ -d $TOOLS/AWSGen ]]; then
    echo -e "$GREEN""[+] Updating AWSGen.""$NC"
    cd $TOOLS/AWSGen
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing AWSGen.""$NC"
    git clone https://github.com/m4ll0k/AWSGen.py $TOOLS/AWSGen
  fi
}

install_paramspider() {
  if [[ -d $TOOLS/ParamSpider ]]; then
    echo -e "$GREEN""[+] Updating ParamSpider.""$NC"
    cd $TOOLS/ParamSpider
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing ParamSpider.""$NC"
    git clone https://github.com/devanshbatham/ParamSpider $TOOLS/ParamSpider
    cd $TOOLS/ParamSpider
    python3 -m pip install -r requiremenets.txt
    cd -
  fi
  mv $TOOLS/ParamSpider/gf_profiles/*.json $HOME/.gf
}

install_commix() {
  if [[ -d $TOOLS/commix ]]; then
    echo -e "$GREEN""[+] Updating commix.""$NC"
    cd $TOOLS/commix
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing commix.""$NC"
    git clone https://github.com/commixproject/commix.git $TOOLS/commix
  fi
}

install_ssrfmap() {
  if [[ -d $TOOLS/SSRFmap ]]; then
    echo -e "$GREEN""[+] Updating SSRFmap.""$NC"
    cd $TOOLS/SSRFmap
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing SSRFmap.""$NC"
    git clone https://github.com/swisskyrepo/SSRFmap $TOOLS/SSRFmap
    cd $TOOLS/SSRFmap
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_secretfinder() {
  if [[ -d $TOOLS/SecretFinder ]]; then
    echo -e "$GREEN""[+] Updating SecretFinder.""$NC"
     cd $TOOLS/SecretFinder
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing SecretFinder.""$NC"
    git clone https://github.com/m4ll0k/SecretFinder.git $TOOLS/SecretFinder
    cd $TOOLS/SecretFinder
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_urldedupe() {
  if [[ -d $TOOLS/urldedupe ]]; then
    echo -e "$GREEN""[+] Updating urldedupe.""$NC"
    cd $TOOLS/urldedupe
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing urldedupe.""$NC"
    git clone https://github.com/ameenmaali/urldedupe.git $TOOLS/urldedupe
  fi
  echo -e "$GREEN""[+] Compiling urldedupe from source.""$NC"
  cd $TOOLS/urldedupe
  cmake CMakeLists.txt
  make
  cd -
}

install_bass() {
  if [[ -d $TOOLS/bass ]]; then
    echo -e "$GREEN""[+] Updating bass.""$NC"
    cd $TOOLS/bass
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing bass.""$NC"
    git clone https://github.com/Abss0x7tbh/bass $TOOLS/bass
    cd $TOOLS/bass
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_dnsgen() {
  if [[ -d $TOOLS/dnsgen ]]; then
    echo -e "$GREEN""[+] Updating dnsgen.""$NC"
     cd $TOOLS/dsngen
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing dnsgen.""$NC"
    git clone https://github.com/ProjectAnte/dnsgen $TOOLS/dnsgen
    cd $TOOLS/dnsgen
    python3 -m pip install -r requirements.txt
    python3 setup.py install
    cd -
  fi
}

install_retiredjs(){
  echo -e "$GREEN""[+] Installing retired.js.""$NC"
  sudo npm install -g retire

}

install_nmapbootstrap() {
  if [[ -f $TOOLS/nmap-bootstrap.xsl ]]; then
    echo -e "$GREEN""[+] Already have nmap bootstrap file installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing nmap bootstrap file.""$NC"
    cd $TOOLS
    wget https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl
    cd -
  fi

}

install_altdns(){
  if [[ -d $TOOLS/altdns ]]; then
    echo -e "$GREEN""[+] Updating altdns.""$NC"
    cd $TOOLS/altdns
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing altdns.""$NC"
    git clone https://github.com/infosec-au/altdns $TOOLS/altdns
    cd $TOOLS/altdns
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_subdomainizer(){
  if [[ -d $TOOLS/SubDomainizer ]]; then
    echo -e "$GREEN""[+] Updating subdomainizer.""$NC"
    cd $TOOLS/SubDomainizer
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing subdomainizer.""$NC"
    git clone https://github.com/nsonaniya2010/SubDomainizer.git $TOOLS/SubDomainizer
    cd $TOOLS/SubDomainizer
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_domlink(){
  if [[ -d $TOOLS/DomLink ]]; then
    echo -e "$GREEN""[+] Updating domlink.""$NC"
    cd $TOOLS/DomLink
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing domlink.""$NC"
    git clone https://github.com/vysecurity/DomLink $TOOLS/DomLink
    cd $TOOLS/DomLink
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_asnlookup(){
  if [[ -d $TOOLS/Asnlookup ]]; then
    echo -e "$GREEN""[+] Updating Asnlookup.""$NC"
    cd $TOOLS/Asnlookup
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing Asnlookup.""$NC"
    git clone https://github.com/yassineaboukir/Asnlookup $TOOLS/Asnlookup
    cd $TOOLS/Asnlookup
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_searchsploit(){
  if [[ -d $TOOLS/exploitdb ]]; then
    echo -e "$GREEN""[+] Already have exploitdb installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing exploitdb.""$NC"
    git clone https://github.com/offensive-security/exploitdb.git $TOOLS/exploitdb
    sudo ln -sf $TOOLS/exploitdb/searchsploit /usr/local/bin/searchsploit
  fi
}

install_ssrfire(){
  if [[ -d $TOOLS/SSRFire ]]; then
    echo -e "$GREEN""[+] Already have SSRFire installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing SSRFire.""$NC"
    git clone https://github.com/micha3lb3n/SSRFire $TOOLS/SSRFire
  fi
}

install_xforwardy(){
  if [[ -d $TOOLS/xforwardy ]]; then
    echo -e "$GREEN""[+] Updating xforwardy.""$NC"
    cd $TOOLS/xforwardy
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing xforwardy.""$NC"
    git clone https://github.com/roottusk/xforwardy.git $TOOLS/xforwardy
    cd $TOOLS/xforwardy
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_cloudunflare(){
  if [[ -d $TOOLS/cloudunflare ]]; then
    echo -e "$GREEN""[+] Already have cloudunflare installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing cloudunflare.""$NC"
    git clone https://github.com/greycatz/CloudUnflare.git $TOOLS/CloudUnflare
  fi
}

install_cewl(){
  if [[ -d $TOOLS/CeWL ]]; then
    echo -e "$GREEN""[+] Already have CeWL installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing CeWL.""$NC"
    git clone https://github.com/digininja/CeWL $TOOLS/CeWL
  fi
}


install_fdsploit(){
  if [[ -d $TOOLS/FDsploit ]]; then
    echo -e "$GREEN""[+] Updating FDsploit.""$NC"
    cd $TOOLS/FDsploit
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing FDsploit.""$NC"
    git clone https://github.com/chrispetrou/FDsploit $TOOLS/FDsploit
    cd $TOOLS/FDsploit
    python3 -m pip install -r requirements.txt
    cd -
  fi
}

install_aquatone(){
  if [[ -d $TOOLS/aquatone ]]; then
    echo -e "$GREEN""[+] Aquatone is already installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing aquatone.""$NC"
    cd $TOOLS
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
    mkdir aquatone
    mv aquatone_linux_amd64_1.7.0.zip aquatone/
    cd aquatone
    unzip aquatone_linux_amd64_1.7.0.zip
    rm -f aquatone_linux_amd64_1.7.0.zip
    cd -
  fi
}

#https://github.com/Zarcolio/sitedorks

install_lists(){
  if [[ -f $TOOLS/lists/all.txt ]]; then
    echo -e "$GREEN""[+] jason haddix all.txt is already installed.""$NC"
  else
    echo -e "$GREEN""[+] Installing jason haddix all.txt.""$NC"
    wget https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O $TOOLS/lists/all.txt
  fi
  if [[ -d $TOOLS/lists/commonspeak2-wordlists ]]; then
    echo -e "$GREEN""[+] Updating commonspeak2-wordlists.""$NC"
    cd $TOOLS/lists/commonspeak2-wordlists
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing commonspeak2's wordlists.""$NC"
    git clone https://github.com/assetnote/commonspeak2-wordlists $TOOLS/lists/commonspeak2-wordlists
  fi
  if [[ -d $TOOLS/lists/1ndiwordlist ]]; then
    echo -e "$GREEN""[+] Updating 1ndiwordlist.""$NC"
    cd $TOOLS/lists/1ndiwordlist
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing 1ndiwordlist wordlists.""$NC"
    git clone https://github.com/1ndianl33t/1ndiwordlist $TOOLS/lists/1ndiwordlist
  fi
  if [[ -d $TOOLS/lists/fuzzmost ]]; then
    echo -e "$GREEN""[+] Updating fuzzmost.""$NC"
    cd $TOOLS/lists/fuzzmost
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing fuzzmost wordlists.""$NC"
    git clone https://github.com/1ndianl33t/fuzzmost $TOOLS/lists/fuzzmost
  fi
  if [[ -d $TOOLS/lists/PayloadsAllTheThings ]]; then
    echo -e "$GREEN""[+] Updating PayloadsAllTheThings.""$NC"
    cd $TOOLS/lists/PayloadsAllTheThings
    git pull
    cd -
  else
    echo -e "$GREEN""[+] Installing PayloadsAllTheThings wordlists.""$NC"
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings $TOOLS/lists/PayloadsAllTheThings
  fi
  if [[ -d $TOOLS/lists/payloads ]]; then
    echo "$GREEN""[+] Already have payloads installed.""$NC"
  else
    echo "$GREEN""[+] Installing All payloads lists!""$NC"
    git clone https://github.com/foospidy/payloads $TOOLS/lists/payloads
    cd $TOOLS/lists/payloads
    bash get.sh
    cd -
  fi
  if [[ -d $TOOLS/lists/xss ]]; then
    echo "$GREEN""[+] Already have XSS payloading installed.""$NC"
  else
    echo "$GREEN""[+] Installing XSS payloads.""$NC"
    mkdir $TOOLS/lists/xss
    wget https://github.com/m4ll0k/Markdown-XSS-Payloads/raw/master/Markdown-XSS-Payloads.txt -O $TOOLS/lists/xss/Markdown-XSS-Payloads.txt
    wget https://gist.githubusercontent.com/kurobeats/9a613c9ab68914312cbb415134795b45/raw/0cabac66ba1afe03c17a72a3ca6c66b0666457b8/xss_vectors.txt -O $TOOLS/lists/xss/xss_vectors.txt
  fi
}

install_main() {
  echo -e "$GREEN""[+] Installing.""$NC"
  sudo apt update -y
  sudo apt upgrade -y
  sudo apt install ruby-dev git wget curl nmap git whatweb wafw00f unzip gcc make libpcap-dev python3.8 jq python3-pip python2.7 python2 gem npm brutespray medusa wireshark dnsutils whois cmake chromium-browser xsltproc -y
  install_pastebin_scraper
  install_eyewitness
  install_openredirex
  install_archievefuzz
  install_passivehunter
  install_theharvester
  install_linkfinder
  install_rue
  install_waybackrobots
  install_waybacksqliscanner
  install_sqlmap
  install_identywaf
  install_dnsvalidator
  install_xsstrike
  install_arjun
  install_cmseek
  install_xsrfprobe
  install_corsy
  install_tplmap
  install_wpscan
  install_crlftest
  install_masscan
  install_corstest
  install_s3scanner
  install_massdns
  install_metasploit
  install_lists
  install_massdns
  install_aquatone
  install_corstest
  install_s3scanner
  install_smuggler
  install_ssrf
  install_getjswords
  install_getrelations
  install_awsgen
  install_swfpfinder
  install_commix
  install_ssrfmap
  install_secretfinder
  install_urldedupe
  install_bass
  install_dnsgen
  install_retiredjs
  install_nmapbootstrap
  install_altdns
  install_subdomainizer
  install_domlink
  install_asnlookup
  install_searchsploit
  install_ssrfire
  install_xforwardy
  install_cloudunflare
  install_fdsploit
  install_cewl
  #install_aquatone
  install_go
  install_go_tools
}

install_main

echo -e "$ORANGE""[i] Note: In order to use S3Scanner, you must configure your personal AWS credentials in the aws CLI tool.""$NC"
echo -e "$ORANGE""[i] See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html for details.""$NC"
echo -e "$ORANGE""[!] Most tools use api keys in their configuration files if you fill them in you will retreive more data.""$NC"
