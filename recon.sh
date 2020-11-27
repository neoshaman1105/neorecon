# Use the output of this to make .scope files for checkscope
getscope(){
  mkdir scope
  rescope --burp -u $1 -o scope/burpscope.json
  rescope --zap --name inscope -u $1 -o scope/zapscope.context
}

getfreshresolvers(){
  dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o ~/tools/lists/my-lists/resolvers
}

#!/bin/bash

# FIX
bf-subdomains(){
  cat wildcard.domains | while read line; do
    shuffledns -d $line -w ~/tools/lists/all.txt -r ~/tools/lists/my-lists/resolvers -massdns ~/tools/massdns/bin/massdns -o $line.shuffle.bf.subdomains
  done
  cat *.shuffledns.bf.subdomains | sort -u >> bf.subdomains
}

rapid7search(){
  cat wildcard.domains | while read line; do
    python3.8 ~/tools/Passivehunter/passivehunter.py $line
  done
  cat *.txt | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' >> unsorted.rapid7.subdomains
  rm -f *.txt
  sort -u unsorted.rapid7.subdomains -o sorted.rapid7.subdomains
  rm -f unsorted.rapid7.subdomains
}

#add vhost from httpx
subdomain-enum(){
  cat hosts | egrep -v '(\.\*$)' | egrep '(^\*.)' | cut -c 3- >> wildcard.domains
  cat hosts | egrep -v '(^\*.)' | egrep -v '(\.\*$)' >> sorted.all.subdomains
  #cat hosts | egrep '(\.\*$)' | sed 's/\*.//g'>> tld.wildcards
  #bf-subdomains
  rapid7search
  cat wildcard.domains | while read line; do
    assetfinder -subs-only $line | grep $line | tee -a assetfinder.subdomains
  done
  subfinder -silent -o subfinder.subdomains -dL wildcard.domains -rL ~/tools/lists/my-lists/resolvers
  cat assetfinder.subdomains subfinder.subdomains sorted.rapid7.subdomains >> all.subdomains
  rm -f assetfinder.subdomains subfinder.subdomains sorted.rapid7.subdomains
  amass enum -nf all.subdomains -v -passive -config ~/amass/config.ini -df wildcard.domains -o amass.passive.subdomains -rf ~/tools/lists/my-lists/resolvers 
  amass enum -nf all.subdomains -v -ip -active -config ~/amass/config.ini -df wildcard.domains -o amass.active.subdomains -min-for-recursive 2 -rf ~/tools/lists/my-lists/resolvers
  cat amass.passive.subdomains | anew all.subdomains 
  awk '{print $1}' amass.active.subdomains | anew all.subdomains
  awk '{print $2}' amass.active.subdomains | tr ',' '\n' | grep -E '\b((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.)){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b' | sort -u >> ipv4.ipaddresses
  awk '{print $2}' amass.active.subdomains | tr ',' '\n' | grep -E '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))' >> ipv6.ipaddresses
  cat all.subdomains | sort -u >> sorted.all.subdomains
  rm -f all.subdomains wildcard.domains amass.passive.subdomains
  #amass db -json amass.db.json -df sorted.all.subdomains
  #amass viz -maltego -df wildcard.domains
}

dnsrecords() {
  mkdir dnshistory
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t A -o S -w dnshistory/A-records
  cat dnshistory/A-records | awk '{print $3}' | grep -E '\b((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.)){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b' | sort -u | anew ipv4.ipaddresses
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t AAAA -o S -w dnshistory/AAAA-records
  cat dnshistory/AAAA-records | awk '{print $3}' | grep -E '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))' | sort -u | anew ipv6.ipaddresses
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t CNAME  -o S -w dnshistory/CNAME-records
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t MX  -o S -w dnshistory/MX-records
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t NS  -o S -w dnshistory/NS-records
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t SOA -o S -w dnshistory/SOA-records
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t PTR -o S -w dnshistory/PTR-records
  cat sorted.all.subdomains | ~/tools/massdns/bin/massdns -r ~/tools/lists/my-lists/resolvers -t TXT -o S -w dnshistory/TXT-records
  cat dnshistory/* | awk -F '. ' '{print $1}' | sort -u >> resolved.all.subdomains
}

getalive() {
  # sperate http and https compare if http doest have or redirect to https put in seperate file
  # compare if you go to https if it automaticly redirects to https if not when does it in the page if never
  cat resolved.all.subdomains | httpx -follow-redirects -content-length -status-code -web-server -silent | tee -a all.alive.subdomains.report
  awk '{print $1}' all.alive.subdomains.report >> all.alive.subdomains 
  
  cat ipv4.ipaddresses | httpx -follow-redirects -content-length -status-code -web-server -silent | tee -a all.alive.ips.report
  awk '{print $1}' all.alive.ips.report >> all.alive.ips
  cat all.alive.ips all.alive.subdomains | sort -u >> all.alive
}

scanner() {
  # cloudunflare cf-check
  # do udp scan as well U:0-65535
  cat ipv4.ipaddresses | cf-check >> ipv4.ipaddresses.cf.free
  sudo ~/tools/masscan/bin/masscan -p0-65535 --rate 1000 --wait 1 -iL ipv4.ipaddresses.cf.free -oX masscan.xml --exclude 255.255.255.255
  sudo rm paused.conf -f
  open_ports=$(cat masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
  cat masscan.xml | grep portid | cut -d "\"" -f 4 | sort -V | uniq >> nmap_targets.tmp
  
  # -sUT --script nmap-vulners
  sudo nmap -sSV -p $open_ports -vvv -Pn -n -T3 -iL nmap_targets.tmp -oX nmap.ipv4.xml --script vulscan
  sudo rm nmap_targets.tmp
  xsltproc -o nmap-bootstrap.ipv4.html ~/tools/nmap-bootstrap.xsl nmap.ipv4.xml

  #learn more about ipv6
  [ -f ipv6.ipaddresses ] && sudo nmap -6 -sSV -p $open_ports -Pn -n -iL ipv6.ipaddresses -oX nmap.ipv6.xml && \
  xsltproc -o nmap-bootstrap.ipv6.html ~/tools/nmap-bootstrap.xsl nmap.ipv6.xml
}

#add port from port scan for possible screenshots
screenshot() {
  cat all.alive | aquatone
}

#add ports that have webfacing interface
gaurecon() {
  mkdir gau-data
  mkdir gau-data/crawler

  echo "${green}Gathering All URLs... ${reset}"
  cat all.alive | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | gau | tee -a gau-data/all.gau.urls

  # add proxy to burp
  gospider -S all.alive -c 10 -u web -d 3 -k 1 --sitemap --robots --blacklist ".(otf|woff|pdf|png|jpeg|css|ico|doc|gif)" -o gau-data/crawler/data
}

#  CHECK IF ALL ALIVE PUT IN SEPERATE FOLDER
checkurls(){
  mkdir potential

  cat gau-data/crawler/data/* | grep '\[url\]' | awk -F '-' '{print $4}' >> gau-data/crawler/all.crawled.urls
  cat gau-data/crawler/data/* | grep '\[aws-s3\]' | awk '{print $3}' | sort -u >> gau-data/crawler/s3.look.into
  cat gau-data/crawler/data/* | grep '\[subdomains\]' | awk '{print $3}' | sort -u >> gau-data/crawler/subdomains
  cat gau-data/crawler/data/* | grep '\[linkfinder\]' | awk '{print $6}' | sort -u >> gau-data/crawler/linkfinder.paths
  cat gau-data/crawler/data/* | grep '\[javascript\]' | awk '{print $3}' | sort -u >> gau-data/crawler/js.paths
  cat gau-data/crawler/data/* | grep '\[form\]' | awk '{print $3}' | sort -u >> gau-data/crawler/forms.urls
  cat gau-data/crawler/data/* | grep '\[robots\]' | awk '{print $3}' | sort -u >> gau-data/crawler/robots.urls
  cat gau-data/crawler/data/* | grep '\[sitemap\]' | awk '{print $3}' | sort -u >> gau-data/crawler/sitemap.urls
  cat gau-data/all.gau.urls gau-data/crawler/all.crawled.urls | sort -u >> gau-data/all.urls

  cat gau-data/all.urls | gf interestingEXT >> potential/interestingext.urls
  cat gau-data/all.urls | gf img-traversal >> potential/imgtraversal.urls
  cat gau-data/all.urls | gf interestingsubs >> potential/interestingsubs.urls
  cat gau-data/all.urls | gf wordpress gf wordpress | awk -F ':' '{print $4}' | sed 's/^/https\:/g' >> potential/wordpress.urls
  cat gau-data/all.urls | gf interestingparams | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.interestingparams.urls
  cat gau-data/all.urls | gf xss | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.xss.urls
  cat gau-data/all.urls | gf redirect | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.redirect.urls
  cat gau-data/all.urls | gf ssti | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.ssti.urls
  cat gau-data/all.urls | gf sqli | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.sqli.urls
  cat gau-data/all.urls | gf ssrf | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.ssrf.urls
  cat gau-data/all.urls | gf rce | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.rce.urls
  cat gau-data/all.urls | gf lfi | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.lfi.urls
  cat gau-data/all.urls | gf idor | ~/tools/urldedupe/urldedupe -s | hakcheckurl | grep 200 | awk '{print $2}' >> potential/alive.idor.urls
  cat gau-data/all.urls | gf debug_logic >> potential/debug_logic.urls

  cat gau-data/all.urls |  grep "?" | unfurl --unique keys | sort -u >> gau-data/params
  [ -s gau-data/params ] && echo "${yellow}Found : $(wc -l gau-data/params | awk '{print $1}') : parameters ${reset}"

  cat gau-data/all.urls | unfurl --unique paths | sort -u >> gau-data/paths
  cat gau-data/paths | cut -c 2- | sort -u >> gau-data/paths.wobs
  [ -s gau-data/paths.wobs ] && echo "${yellow}Found : $(wc -l gau-data/paths.wobs | awk '{print $1}') : paths ${reset}"

  cat gau-data/all.urls | grep -P "\w+\.json(\?|$)" | sort -u >> gau-data/jsonurls
  [ -s gau-data/jsonurls ] && echo "Found : $(wc -l gau-data/jsonurls | awk '{print $1}') : json files"
  cat gau-data/jsonurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.jsonurls
  [ -s gau-data/alive.jsonurls ] && echo "Found : $(wc -l gau-data/alive.txturls | awk '{print $1}') : alive text files"


  cat gau-data/all.urls | grep -P "\w+\.txt(\?|$)" | sort -u >> gau-data/txturls
  [ -s gau-data/txturls ] && echo "Found : $(wc -l gau-data/txturls | awk '{print $1}') : text files"
  cat gau-data/txturls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.txturls
  [ -s gau-data/alive.txturls ] && echo "Found : $(wc -l gau-data/alive.txturls | awk '{print $1}') : alive text files"

  cat gau-data/all.urls | grep -P "\w+\.jst(\?|$)" | sort -u >> gau-data/jsturls
  [ -s gau-data/jsturls ] && echo "Found : $(wc -l gau-data/jsturls | awk '{print $1}') : jst files"
  cat gau-data/jsturls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.jsturls
  [ -s gau-data/alive.jsturls ] && echo "Found : $(wc -l gau-data/alive.jsturls | awk '{print $1}') : alive jst files"

  cat gau-data/all.urls | grep -P "\w+\.do(\?|$)" | sort -u >> gau-data/dourls
  [ -s gau-data/dourls ] && echo "Found : $(wc -l gau-data/dourls | awk '{print $1}') : do files"
  cat gau-data/dourls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.dourls
  [ -s gau-data/alive.dourls ] && echo "Found : $(wc -l gau-data/alive.dourls | awk '{print $1}') : alive do files"

  cat gau-data/all.urls | grep -P "\w+\.js(\?|$)" | sort -u >> gau-data/jsurls
  [ -s gau-data/jsurls ] && echo "Found : $(wc -l gau-data/jsurls | awk '{print $1}') : javascript files"
  cat gau-data/jsurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.jsurls
  [ -s gau-data/alive.jsurls ] && echo "Found : $(wc -l gau-data/alive.jsurls | awk '{print $1}') : alive javascript files"

  cat gau-data/all.urls | grep -P "\w+\.php(\?|$)" | sort -u >> gau-data/phpurls
  [ -s gau-data/phpurls ] && echo "Found : $(wc -l gau-data/phpurls | awk '{print $1}') : php files "
  cat gau-data/phpurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.phpurls
  [ -s gau-data/alive.phpurls ] && echo "${yellow}Found : $(wc -l gau-data/alive.phpurls | awk '{print $1}') : alive php files"

  cat gau-data/all.urls | grep -P "\w+\.aspx(\?|$)" | sort -u >> gau-data/aspxurls
  [ -s gau-data/aspxurls ] && echo "Found : $(wc -l gau-data/aspxurls | awk '{print $1}') : aspx files"
  cat gau-data/aspxurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.aspxurls
  [ -s gau-data/alive.aspxurls ] && echo "Found : $(wc -l gau-data/alive.aspxurls | awk '{print $1}') : alive aspx files"

  cat gau-data/all.urls | grep -P "\w+\.asp(\?|$)" | sort -u >> gau-data/aspurls
  [ -s gau-data/aspurls ] && echo "Found : $(wc -l gau-data/aspurls | awk '{print $1}') : asp files"
  cat gau-data/aspurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.aspurls
  [ -s gau-data/alive.aspurls ] && echo "Found : $(wc -l gau-data/alive.aspurls | awk '{print $1}') : alive asp files"

  cat gau-data/all.urls | grep -P "\w+\.jsp(\?|$)" | sort -u >> gau-data/jspurls
  [ -s gau-data/jspurls ] && echo "Found : $(wc -l gau-data/jspurls | awk '{print $1}') : javascript page files"
  cat gau-data/jspurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.jspurls
  [ -s gau-data/alive.jspurls ] && echo "Found : $(wc -l gau-data/alive.jspurls | awk '{print $1}') : alive javascript page files"

  cat gau-data/all.urls | grep -P "\w+\.xml(\?|$)" | sort -u >> gau-data/xmlurls
  [ -s gau-data/xmlurls ] && echo "Found : $(wc -l gau-data/xmlurls | awk '{print $1}') : xml files"
  cat gau-data/xmlurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.xmlurls
  [ -s gau-data/alive.xmlurls ] && echo "Found : $(wc -l gau-data/alive.xmlurls | awk '{print $1}') : alive xml files"

  cat gau-data/all.urls | grep -P "\w+\.cgi(\?|$)" | sort -u >> gau-data/cgiurls
  [ -s gau-data/cgiurls ] && echo "Found : $(wc -l gau-data/cgiurls | awk '{print $1}') : cgi files"
  cat gau-data/cgiurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.cgiurls
  [ -s gau-data/alive.cgiurls ] && echo "Found : $(wc -l gau-data/alive.cgiurls | awk '{print $1}') : alive cgi files"

  cat gau-data/all.urls | grep -P "\w+\.py(\?|$)" | sort -u >> gau-data/pyurls
  [ -s gau-data/pyurls ] && echo "Found : $(wc -l gau-data/aspxurls | awk '{print $1}') : python files"
  cat gau-data/pyurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.pyurls
  [ -s gau-data/alive.pyurls ] && echo "Found : $(wc -l gau-data/alive.pyurls | awk '{print $1}') : alive python files"

  cat gau-data/all.urls | grep -P "\w+\.bak(\?|$)" | sort -u >> gau-data/bakurls
  [ -s gau-data/bakurls ] && echo "Found : $(wc -l gau-data/bakurls | awk '{print $1}') : backup files"
  cat gau-data/bakurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.bakurls
  [ -s gau-data/alive.bakurls ] && echo "Found : $(wc -l gau-data/alive.bakurls | awk '{print $1}') : alive backup files"

  cat gau-data/all.urls | grep -P "\w+\.csv(\?|$)" | sort -u >> gau-data/csvurls
  [ -s gau-data/csvurls ] && echo "Found : $(wc -l gau-data/csvurls | awk '{print $1}') : csv files"
  cat gau-data/csvurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.csvurls
  [ -s gau-data/alive.csvurls ] && echo "Found : $(wc -l gau-data/alive.csvurls | awk '{print $1}') : alive csv files"

  cat gau-data/all.urls | grep -P "\w+\.db(\?|$)" | sort -u >> gau-data/dburls
  [ -s gau-data/dburls ] && echo "Found : $(wc -l gau-data/dburls | awk '{print $1}') : database files"
  cat gau-data/dburls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.dburls
  [ -s gau-data/alive.dburls ] && echo "Found : $(wc -l gau-data/alive.dburls | awk '{print $1}') : alive database files"

  cat gau-data/all.urls | grep -P "\w+\.cfg(\?|$)" | sort -u >> gau-data/configurls
  [ -s gau-data/configurls ] && echo "Found : $(wc -l gau-data/configurls | awk '{print $1}') : config files"
  cat gau-data/configurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.configurls
  [ -s gau-data/alive.configurls ] && echo "Found : $(wc -l gau-data/alive.configurls | awk '{print $1}') : alive config files"

  cat gau-data/all.urls | grep -P "\w+\.log(\?|$)" | sort -u >> gau-data/logurls
  [ -s gau-data/logurls ] && echo "Found : $(wc -l gau-data/logurls | awk '{print $1}') : log files"
  cat gau-data/logurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.logurls
  [ -s gau-data/alive.logurls ] && echo "Found : $(wc -l gau-data/alive.logurls | awk '{print $1}') : alive log files"

  cat gau-data/all.urls | grep -P "\w+\.sql(\?|$)" | sort -u >> gau-data/sqlurls
  [ -s gau-data/sqlurls ] && echo "Found : $(wc -l gau-data/sqlurls | awk '{print $1}') : sql files"
  cat gau-data/sqlurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.sqlurls
  [ -s gau-data/alive.sqlurls ] && echo "Found : $(wc -l gau-data/alive.sqlurls | awk '{print $1}') : alive sql files"

  cat gau-data/all.urls | grep -P "\w+\.msi(\?|$)" | sort -u >> gau-data/msiurls
  [ -s gau-data/msiurls ] && echo "Found : $(wc -l gau-data/csvurls | awk '{print $1}') : Windows installer package files"
  cat gau-data/msiurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.msiurls
  [ -s gau-data/alive.msiurls ] && echo "Found : $(wc -l gau-data/alive.msiurls | awk '{print $1}') : alive Windows installer package files"

  cat gau-data/all.urls | grep -P "\w+\.csv(\?|$)" | sort -u >> gau-data/csvurls
  [ -s gau-data/csvurls ] && echo "Found : $(wc -l gau-data/csvurls | awk '{print $1}') : csv files"
  cat gau-data/csvurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.csvurls
  [ -s gau-data/alive.csvurls ] && echo "Found : $(wc -l gau-data/alive.csvurls | awk '{print $1}') : alive csv files"

  cat gau-data/all.urls | grep -P "\w+\.cfm(\?|$)" | sort -u >> gau-data/cfmurls
  [ -s gau-data/cfmurls ] && echo "Found : $(wc -l gau-data/cfmurls | awk '{print $1}') : cold fusion files"
  cat gau-data/cfmurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.cfmurls
  [ -s gau-data/alive.cfmurls ] && echo "Found : $(wc -l gau-data/alive.cfmurls | awk '{print $1}') : alive cold fusioin files"

  cat gau-data/all.urls | grep -P "\w+\.wsf(\?|$)" | sort -u >> gau-data/wsfurls
  [ -s gau-data/wsfurls ] && echo "Found : $(wc -l gau-data/wsfurls | awk '{print $1}') : windows script files"
  cat gau-data/wsfurls | hakcheckurl | grep 200 | awk '{print $2}' | sort -u >> gau-data/alive.wsfurls
  [ -s gau-data/alive.wsfurls ] && echo "Found : $(wc -l gau-data/alive.wsfurls | awk '{print $1}') : alive window script files"
}

getcms(){
  cat all.alive.subdomains | while read line; do
    whatweb -U "$UA" $line | tee -a all.cms
  done
}

makewordlists(){
  mkdir wordlists
  
  cat gau-data/all.urls gau-data/crawler/linkfinder.paths all.js.urls gau-data/paths.wobs | sort -u | wordlistgen -qv >> wordlists/urlComponents
  cat gau-data/all.urls gau-data/crawler/linkfinder.paths all.js.urls gau-data/paths.wobs | sort -u | wordlistgen -fq >> wordlists/paths
 
  cat gau-data/all.urls | 1ndiList -param -t 50 -o wordlists/
  mv wordlists/params.txt wordlists/params
  cat gau-data/params | anew wordlists/params
}

bf-custom(){
  ffuf -u FUZZ1FUZZ2 -w all.alive.subdomains:FUZZ1 -w wordlists/urlComponents:FUZZ2 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" -r -c -mc 100,101,102,200,201,202,203,206,207,208,226,302,304,305,306,307,401,402,403,407,418,417,500,504 -o content-discovery/ffuf.bf.wayback.json -t 50 -replay-proxy http://127.0.0.1:8080
}

bf-quickhit(){
  ffuf -u FUZZ1FUZZ2 -w all.alive.subdomains:FUZZ1 -w ~/tools/lists/my-lists/quick:FUZZ2 -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" -r -c -mc 100,101,102,200,201,202,203,206,207,208,226,302,304,305,306,307,401,402,403,407,418,417,500,504 -o content-discovery/ffuf.bf.quickhit.json -t 50 -replay-proxy http://127.0.0.1:8080
}

content-discovery(){
  mkdir content-discovery
  bf-custom
  bf-quickhit
}

checkdomains(){
  subdomain-enum
  dnsrecords
  getalive
  screenshot
}

recon(){
  subdomain-enum
  dnsrecords
  getalive
  scanner
  screenshot
  gaurecon
  checkurls
  getcms
  makewordlists
  content-disovery
}

checknuclei(){
  mkdir nuclei_op
  nuclei -l all.alive -t ~/tools/nuclei-templates/cves/ -c 75 -o nuclei_op/cves -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/files/ -c 75 -o nuclei_op/files -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/panels/ -c 75 -o nuclei_op/panels -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/security-misconfiguration/ -c 75 -o nuclei_op/security-misconfiguration -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/technologies/ -c 75 -o nuclei_op/technologies -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/tokens/ -c 75 -o nuclei_op/tokens -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/vulnerabilities/ -c 75 -o nuclei_op/vulnerabilities -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/generic-detections/ -c 75 -o nuclei_op/basic -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/dns/ -c 75 -o nuclei_op/dns -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/subdomain-takeover/ -c 75 -o nuclei_op/subdomain-takeover -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/default-credentials/ -c 75 -o nuclei_op/defcreds -pbar
  nuclei -l all.alive -t ~/tools/nuclei-templates/sqli/ -c 75 -o nuclei_op/sql-injection -pbar
}
