#------ bug hunting ------

getscope(){
  rescope --burp -u $1 -o burpscope.json
  rescope --zap --name CoolScope -u $1 -o zapscope.context
}

rapid7search(){
  python3.7 ~/tools/Passive-hunter/Passivehunter/passivehunter.py $1
  cat *.com.txt | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' >> unsorted.rapid7.subdomains
  rm -f *.txt
  cat unsorted.rapid7.subdomains | sort -u >> sorted.rapid7.subdomains
  rm -f unsorted.rapid7.subdomains
}

getfreshresolvers(){
  dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o ~/tools/lists/resolvers
}

# USE WITH CAUTION
bf-subdomains(){
  cat hosts | while read line; do
    shuffledns -d $line -w ~/tools/lists/commonspeak2-wordlists-master/subdomains/subdomains.txt -r ~/tools/lists/my-lists/resolvers -o shuffledns.bf.subdomains
  done
}

## findomain
subdomain-enum(){
  subfinder -nW -v -o subfinder.subdomains -dL hosts
  cat subfinder.subdomains sorted.rapid7.subdomains >> all.subdomains
  rm -f subfinder.subdomains sorted.rapid7.subdomains 
  amass enum -nf all.subdomains -v -ip -active -config ~/amass/config.ini -min-for-recursive 3 -df hosts -o amass.subdomains
  awk '{print $1}' amass.subdomains >> all.subdomains
  awk '{print $2}' amass.subdomains | tr ',' '\n' | grep -E '\b((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.)){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b' | sort -u >> ipv4.ipaddresses
  awk '{print $2}' amass.subdomains | tr ',' '\n' | grep -E '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))' >> ipv6.addresses
  sort -u all.subdomains -o sorted.all.subdomains
  rm -f all.subdomains 
}

## change to massdns or make shuffledns output ip addresses
resolving(){
   shuffledns -d $1 -list sorted.all.subdomains -r ~/tools/lists/my-lists/resolvers -o resolved.all.subdomains
}

#############
#Ex: of .scope file 
# .*\.example\.com$
# ^example\.com$
# .*\.example\.net$
# !.*outofscope\.example\.net$
##########
checkscope(){
  cat resolved.all.subdomains | inscope | tee -a all.subdomains.inscope
}

getalive() {
  # sperate http and https compare if http doest have or redirect to https put in seperate file
  # compare if you go to https if it automaticly redirects to https if not when does it in the page if never
  cat all.subdomains.inscope | httprobe -c 10 -t 3000 | sort -u >> alive.all.subdomains
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | sort -u | while read line; do
    probeurl=$(cat alive.all.subdomains | sort -u | grep -m 1 $line)
    echo "$probeurl" >> cleaned.alive.all.subdomains
  done
  echo "$(cat cleaned.alive.sudomains | sort -u)" > cleaned.alive.all.subdomains
}


dnsrecords() {
  mkdir dnshistory
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r A -silent -o dnshistory/A-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r NS -silent -o dnshistory/NS-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r CNAME -silent -o dnshistory/CNAME-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r SOA -silent -o dnshistory/SOA-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r PTR -silent -o dnshistory/PTR-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r MX -silent -o dnshistory/MX-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r TXT  -silent -o dnshistory/TXT-records
  cat alive.all.subdomains | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | dnsprobe -s ~/tools/lists/my-lists/resolvers -r AAAA -silent -o dnshistory/AAAA-records
}

screenshot() { 
  #python3 EyeWitness.py --web -f cleaned.alive.all.subdomains --user-agent "$UA" --show-selenium --resolve -d eyewitness-report
  cat alive.all.subdomains | ~/tools/aquatone/aquatone -chrome-path /snap/bin/chromium -out aqua_out
}

getrobots(){
  cat hosts | while read line; do 
    python3 ~/tools/waybackrobots.py $line
  done
  cat *-robots.txt | cut -c -2 | sort -u >> wayback-data/robots.paths.wobs
}

waybackrecon() {
  ## check whats alive and save them in there own seperate files (hakcheckurl, drishti)
  mkdir wayback-data/
  getrobots
  echo "${green}Scraping wayback for data... ${reset}"

  cat alive.all.subdomains | waybackurls | sort -u >> wayback-data/waybackurls

  cat wayback-data/waybackurls | unfurl --unique keys | sort -u >> wayback-data/params
  [ -s wayback-data/params ] && echo "${yellow}Found : $(wc -l wayback-data/params | awk '{print $1}') : parameters ${reset}"

  cat wayback-data/waybackurls | unfurl --unique values | sort -u >> wayback-data/values
  [ -s wayback-data/values ] && echo "${yellow}Found : $(wc -l  wayback-data/values | awk '{print $1}') : values for parameters ${reset}"

  cat wayback-data/waybackurls | unfurl --unique domains | sort -u >> wayback-data/domains
  [ -s wayback-data/domains ] && echo "${yellow}Found : $(wc -l wayback-data/domains | awk '{print $1}') : domains ${reset}"

  cat wayback-data/waybackurls | unfurl --unique paths | sort -u >> wayback-data/paths
  cat wayback-data/paths | cut -c 2- | sort -u >> wayback-data/paths.wobs
  [ -s wayback-data/paths ] && echo "${yellow}Found : $(wc -l wayback-data/paths | awk '{print $1}') : paths ${reset}"

  cat wayback-data/waybackurls | unfurl --unique format %S | sort -u >> wayback-data/subdomains
  [ -s wayback-data/subdomains ] && echo "${yellow}Found : $(wc -l wayback-data/subdomains | awk '{print $1}') : subdomains ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.js(\?|$)" | sort -u >> wayback-data/jsurls
  [ -s wayback-data/jsurls ] && echo "${yellow}Found : $(wc -l wayback-data/jsurls | awk '{print $1}') : javascript files ${reset}" 

  cat wayback-data/waybackurls | grep -P "\w+\.php(\?|$)" | sort -u >> wayback-data/phpurls
  [ -s $domain/$foldername/wayback-data/phpurls ] && echo "${yellow}Found : $(wc -l $domain/$foldername/wayback-data/phpurls | awk '{print $1}') : php files ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.aspx(\?|$)" | sort -u >> wayback-data/aspxurls
  [ -s wayback-data/aspxurls ] && echo "${yellow}Found : $(wc -l wayback-data/aspxurls | awk '{print $1}') : aspx files ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.asp(\?|$)" | sort -u >> wayback-data/aspurls
  [ -s wayback-data/aspurls ] && echo "${yellow}Found : $(wc -l wayback-data/aspurls | awk '{print $1}') : asp files ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.jsp(\?|$)" | sort -u >> wayback-data/jspurls
  [ -s wayback-data/jspurls ] && echo "${yellow}Found : $(wc -l wayback-data/jspurls | awk '{print $1}') : javascript Server Pages ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.xml(\?|$)" | sort -u >> wayback-data/xmlurls
  [ -s wayback-data/xmlurls ] && echo "${yellow}Found : $(wc -l wayback-data/xmlurls | awk '{print $1}') : xml files ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.cgi(\?|$)" | sort -u >> wayback-data/cgiurls
  [ -s wayback-data/cgiurls ] && echo "${yellow}Found : $(wc -l wayback-data/cgiurls | awk '{print $1}') : cgi files ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.py(\?|$)" | sort -u >> wayback-data/pyurls
  [ -s wayback-data/pyurls ] && echo "${yellow}Found : $(wc -l wayback-data/pyurls | awk '{print $1}') : python files ${reset}"

  cat wayback-data/waybackurls | grep -P "\w+\.bak(\?|$)" | sort -u >> wayback-data/backupurls
  [ -s wayback-data/backupurls ] && echo "${yellow}Found : $(wc -l wayback-data/backupurls | awk '{print $1}') : backup files ${reset}"
}

scanner() {
  # do udp scan as well
  # sort between ipv4 and ipv6 masscan does not support ipv6 YET
  sudo ~/tools/masscan/bin/masscan --top-ports 10000 --open --rate 100000 --wait 0 -iL ipv4.ipaddresses -oX masscan.xml --exclude 255.255.255.255
  sudo rm paused.conf
  open_ports=$(cat masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
  cat masscan.xml | grep portid | cut -d "\"" -f 4 | sort -V | uniq >> nmap_targets.tmp
  
  sudo nmap -sVC -p $open_ports -v -Pn -n -T4 -iL nmap_targets.tmp -oX nmap.ipv4.xml
  sudo rm nmap_targets.tmp
  xsltproc -o nmap-native.ipv4.html nmap.ipv4.xml
#  xsltproc -o nmap-bootstrap.ipv4.html bootstrap-nmap.xsl nmap.ipv4.xml

#  sudo nmap -sSV --top-ports 1000 -Pn -n -iL ipv6.ipaddresses -oX ipv6.ipaddresses
}

crawler() { 
  cat hosts | while read line; do
    gau -subs $line | tee -a crawler.urls
  done
}

getjsurls() {  
  cat hosts | while read line; do
    cat alive.all.subdomains | subjs -ua "$UA" | grep $line | tee -a js.urls
  done
  cat alive.all.subdomains | getJS -complete -resolve | sort -u | tee -a js.urls
}

linkfindersearch(){
  mkdir js
  mkdir db
  linkf=~/tools/LinkFinder/linkfinder.py
  for i in $(cat alive.all.subdomains)
  do
    n1=$(echo $i | awk -F/ '{print $3}')
    n2=$(echo $i | awk -F/ '{print $1}' | sed 's/.$//')
    mkdir js/$n1-$n2
    mkdir db/$n1-$n2
    timeout 30 python3 $linkf -d -i $i -o cli > js/$n1-$n2/raw.txt

    jslinks=$(cat js/$n1-$n2/raw.txt | grep -oaEi "https?://[^\"\\'> ]+" | grep '\.js' | grep "$n1" | sort -u)

    if [[ ! -z $jslinks ]]; then
      for js in $jslinks
        do
          python3 $linkf -i $js -o cli >> js/$n1-$n2/linkfinder.txt
          echo "$js" >> js/$n1-$n2/jslinks.txt
          wget $js -P db/$n1-$n2/ -q
        done
      fi
  done
}

getjspaths() {
  cat js.urls | while read line; do ruby /home/nickqy/tools/relative-url-extractor-master/extract.rb $line | tee -a js.extracted.paths; done
  cat wayback-data/jsurls | while read line; do ruby /home/nickqy/tools/relative-url-extractor-master/extract.rb $line | tee -a js.extracted.paths; done
  cat js.extracted.paths | sort -u >> sorted.js.paths
  cat sorted.js.paths | cut -c 2- | sort -u >> sorted.js.paths.wobs
  rm -f js.extracted.paths
}


fullrecon() {
  subdomain-enum
  getalive
  screenshot
  waybackrecon
  getjsurls
  getjspaths
}

github_dorks () {
        if [ "$#" -ne 1 ]; then
                echo "${red}Usage: domain_github_dorks <domains>${reset}"
                return
        fi
        #without_suffix=$(awk -F '.' '{print $1}' $1)
        echo ""
        echo "************ Github Dork Links (must be logged in) *******************"
        echo ""
        echo "  password"
        echo "https://github.com/search?q=%22$1%22+password&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+password&type=Code"
        echo ""
        echo " npmrc _auth"
        echo "https://github.com/search?q=%22$1%22+npmrc%20_auth&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+npmrc%20_auth&type=Code"
        echo ""
        echo " dockercfg"
        echo "https://github.com/search?q=%22$1%22+dockercfg&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+dockercfg&type=Code"
        echo ""
        echo " pem private"
        echo "https://github.com/search?q=%22$1%22+pem%20private&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+extension:pem%20private&type=Code"
        echo ""
        echo "  id_rsa"
        echo "https://github.com/search?q=%22$1%22+id_rsa&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+id_rsa&type=Code"
        echo ""
        echo " aws_access_key_id"
        echo "https://github.com/search?q=%22$1%22+aws_access_key_id&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+aws_access_key_id&type=Code"
        echo ""
        echo " s3cfg"
        echo "https://github.com/search?q=%22$1%22+s3cfg&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+s3cfg&type=Code"
        echo ""
        echo " htpasswd"
        echo "https://github.com/search?q=%22$1%22+htpasswd&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+htpasswd&type=Code"
        echo ""
        echo " git-credentials"
        echo "https://github.com/search?q=%22$1%22+git-credentials&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+git-credentials&type=Code"
        echo ""
        echo " bashrc password"
        echo "https://github.com/search?q=%22$1%22+bashrc%20password&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+bashrc%20password&type=Code"
        echo ""
        echo " sshd_config"
        echo "https://github.com/search?q=%22$1%22+sshd_config&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+sshd_config&type=Code"
        echo ""
        echo " xoxp OR xoxb OR xoxa"
        echo "https://github.com/search?q=%22$1%22+xoxp%20OR%20xoxb%20OR%20xoxa&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+xoxp%20OR%20xoxb&type=Code"
        echo ""
        echo " SECRET_KEY"
        echo "https://github.com/search?q=%22$1%22+SECRET_KEY&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+SECRET_KEY&type=Code"
        echo ""
        echo " client_secret"
        echo "https://github.com/search?q=%22$1%22+client_secret&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+client_secret&type=Code"
        echo ""
        echo " sshd_config"
        echo "https://github.com/search?q=%22$1%22+sshd_config&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+sshd_config&type=Code"
        echo ""
        echo " github_token"
        echo "https://github.com/search?q=%22$1%22+github_token&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+github_token&type=Code"
        echo ""
        echo " api_key"
        echo "https://github.com/search?q=%22$1%22+api_key&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+api_key&type=Code"
        echo ""
        echo " FTP"
        echo "https://github.com/search?q=%22$1%22+FTP&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+FTP&type=Code"
        echo ""
        echo " app_secret"
        echo "https://github.com/search?q=%22$1%22+app_secret&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+app_secret&type=Code"
        echo ""
        echo "  passwd"
        echo "https://github.com/search?q=%22$1%22+passwd&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+passwd&type=Code"
        echo ""
        echo " s3.yml"
        echo "https://github.com/search?q=%22$1%22+.env&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+.env&type=Code"
        echo ""
        echo " .exs"
        echo "https://github.com/search?q=%22$1%22+.exs&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+.exs&type=Code"
        echo ""
        echo " beanstalkd.yml"
        echo "https://github.com/search?q=%22$1%22+beanstalkd.yml&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+beanstalkd.yml&type=Code"
        echo ""
        echo " deploy.rake"
        echo "https://github.com/search?q=%22$1%22+deploy.rake&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+deploy.rake&type=Code"
        echo ""
        echo " mysql"
        echo "https://github.com/search?q=%22$1%22+mysql&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+mysql&type=Code"
        echo ""
        echo " credentials"
        echo "https://github.com/search?q=%22$1%22+credentials&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+credentials&type=Code"
        echo ""
        echo " PWD"
        echo "https://github.com/search?q=%22$1%22+PWD&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+PWD&type=Code"
        echo ""
        echo " deploy.rake"
        echo "https://github.com/search?q=%22$1%22+deploy.rake&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+deploy.rake&type=Code"
        echo ""
        echo " .bash_history"
        echo "https://github.com/search?q=%22$1%22+.bash_history&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+.bash_history&type=Code"
        echo ""
        echo " .sls"
        echo "https://github.com/search?q=%22$1%22+.sls&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+PWD&type=Code"
        echo ""
        echo " secrets"
        echo "https://github.com/search?q=%22$1%22+secrets&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+secrets&type=Code"
        echo ""
        echo " composer.json"
        echo "https://github.com/search?q=%22$1%22+composer.json&type=Code"
        echo "https://github.com/search?q=%22$without_suffix%22+composer.json&type=Code"
        echo ""
}

check4phNsq(){
  ~/tools/urlcrazy/urlcrazy -p $1
  #python3 ~/tools/dnstwist/dnstwist.py 
}

redUrl() { 
mkdir redirecttest; cd redirect test
gau -subs $1 | grep "redirect" >> $1_redirectall.txt | gau -subs $1 | grep "redirect=" >> $1_redirectequal.txt | gau -subs $1 | grep "url" >> $1_urlall.txt | gau -subs $1 | grep "url=" >> $1_urlequal.txt | gau -subs $1 | grep "next=" >> $1_next.txt | gau -subs $1 | grep "dest=" >> $1_dest.txt | gau -subs $1 | grep "destination" >> $1_destination.txt | gau -subs $1 | grep "return" >> $1_return.txt | gau -subs $1 | grep "go=" >> $1_go.txt | gau -subs $1 | grep "redirect_uri" >> $1_redirecturi.txt | gau -subs $1 | grep "continue=" >> $1_continue.txt | gau -subs $1 | grep "return_path=" >> $1_path.txt | gau -subs $1 | grep "externalLink=" >> $1_link.txt | gau -subs $1 | grep "URL=" >> $1_URL.txt 
cat * | sort -u >> all-poss-redirects
rm -f *.txt
}

blindssrftest(){
  if [ -z "$1" ]; then
    echo >&2 "ERROR: Domain not set"
    exit 2
  fi
  if [ -z "$2" ]; then
    echo >&2 "ERROR: Sever link not set"
    exit 2
  fi
  if [ -f wayback-data/waybackurls ] && [ -f crawler.urls ]; then
    cat wayack-data/waybackurls crawler.urls | sort -u | grep "?" | qsreplace -a | qsreplace $2 > $1-bssrf
    sed -i "s|$|\&dest=$2\&redirect=$2\&uri=$2\&path=$2\&continue=$2\&url=$2\&window=$2\&next=$2\&data=$2\&reference=$2\&site=$2\&html=$2\&val=$2\&validate=$2\&domain=$2\&callback=$2\&return=$2\&page=$2\&feed=$2\&host=$2&\port=$2\&to=$2\&out=$2\&view=$2\&dir=$2\&show=$2\&navigation=$2\&open=$2|g" $1-bssrf
    echo "Firing the requests - check your server for potential callbacks"
    ffuf -w $1-bssrf -u FUZZ -t 50
  fi
}
