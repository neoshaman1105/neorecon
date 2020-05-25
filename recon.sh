#------ bug hunting/pentesting Tools ------

# OSINT tools
domain_github_dorks () {
        if [ "$#" -ne 1 ]; then
                echo "${red}Usage: domain_github_dorks <domains>${reset}"
                return
        fi
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



#fullOSINT(){
#  domain
#  discord-osint
#  OSRF
#  theharvester
#  recon-ng-v5
#  urlcrazy
#  dnstwist
#}

# Use the output of this to make .scope files for checkscope
getscope(){
  rescope --burp -u hackerone.com/security -o burpscope.json
  rescope --zap --name CoolScope -u hackerone.com/security -o zapscope.context
}
#############
#Ex: of .scope file 
# .*\.example\.com$
# ^example\.com$
# .*\.example\.net$
# !.*outofscope\.example\.net$
##########

rapid7search(){
  python3.7 ~/tools/Passive-hunter/Passivehunter/passivehunter.py $1
  sort output to sorted.rapid7.subdomains
}

subdomain-enum(){
  # THINGS TO ADD
  #save *.(wildcard) subdomains for further recursive subdomain enumeration
  #don't resolve with subfinder or amass then | dnsgen || altdns | massdns 
  subfinder -nW -v -o subfinder.subdomains -dL hosts
  cat subfinder.subdomains sorted.rapid7.subdomains >> all.subdomains
  amass enum -nf all.subdomains -v -ip -active -config ~/amass/config.ini -min-for-recursive 3 -df hosts -o amass.subdomains
  awk '{print $1}' amass.subdomains >> all.subdomains
  sort -u all.subdomains -o sorted.all.subdomains
  rm -f all.subdomains
}

# USE WITH CAUTION
#bf-subdomains(){
#  get fresh dns resolver list for massdns 
#  dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o resolvers.txt
#  shuffledns massdns subbrute 
#  wordlist == jhaddix + commonspeak2 + mine
#  after compare all.subdomais with massdns.subdomains if any are 
#}

###################################
# Learn how amass gets both ipv4&6
####################################
#resolver() {
#  resolve using more than just A and AAAA
#  massdns grep out ipv4 ip's and subdomains
#  output ipv4.ipadresses & sorted.alive.all.subdomains
#}

getalive() {
  # sperate http and https compare if http doest have or redirect to https put in seperate file
  # compare if you go to https if it automaticly redirects to https if not when does it in the page if never
  cat sorted.all.subdomains | httprobe -c 10 -t 5000 | sort -u >> alive.all.subdomains
}


screenshot() {
  cat alive.all.subdomains | ~/tools/aquatone/aquatone -chrome-path /snap/bin/chromium -out aqua_out
}

#crawler() { gocewl BiLE gau  hakrawler
#  get all urls add sorted out the data
#}

getjsurls() {
 #new tool RnD
 #curl or wget crawler to get all .js
  cat alive.all.subdomains | getJS -complete -resolve | sort -u >> js.urls
}

fullrecon() {
  subdomain-enum
  getalive
  screenshot
  waybackrecon
  getjsurls
  getjspaths
}


