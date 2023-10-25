import requests
import pyfiglet
from termcolor import colored
import time
import shodan
from tqdm import tqdm
import sys

def result(shodan_api_key,query):
    results = shodan_api_key.search(query,limit=10)
    if not results or 'matches' not in results or not results['matches']:
        print(colored(" \n No Results Found \n ",'red'))
    else:
        for resultMatch in results['matches']:
            time.sleep(1)
            print("\n")
            print(colored("IP:", 'yellow') + f" {resultMatch['ip_str']}")
            print(colored("Port:", 'yellow') + f" {resultMatch['port']}")
            print(colored("Organization:", 'yellow') + f" {resultMatch['org']}")
            print(colored("ISP:", 'yellow') + f" {resultMatch['isp']}")
            print('')
            time.sleep(2)
def fetch_internet_cameras(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Webcams From Internet.... \n", 'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,'"Server: yawcam" "Mime-Type: text/html"')
    result(shodan_api_key,'("webcam 7" OR "webcamXP") http.component:"mootools" -401')
    print(colored(bold + "\n Fetching Webcams Sensitive Internal Information",'blue')) 
    result(shodan_api_key,'"Server: IP Webcam Server" "200 OK"')
    result(shodan_api_key,'html:"DVR_H264 ActiveX"')    

def fetch_ics(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Industrial Control System Dashboard From Internet....\n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    time.sleep(2)
    print(colored(bold + "\n Fetching Samsung Electronic Billboards... ",'blue'))
    result(shodan_api_key,'"Server: Prismview Player"')
    print(colored(bold + "\n Fetching Gas Station Pump Controllers... ",'blue'))
    result(shodan_api_key,'"in-tank inventory" port:10001')
    print(colored(bold + "\n Fetching IOT License Plate Readers... ",'blue'))
    result(shodan_api_key,'P372 "ANPR enabled"')
    print(colored(bold + "\n Fetching Traffic Light Controllers / Red Light Cameras... ",'blue'))
    result(shodan_api_key,'mikrotik streetlight')
    print(colored(bold + "\n Fetching Voting Machines in the United States... ",'blue'))
    result(shodan_api_key,'"voter system serial" country:US')
    print(colored(bold + "\n Fetching Prison Pay Phones... ",'blue'))
    result(shodan_api_key,'"[2J[H Encartele Confidential"')
    print(colored(bold + "\n Fetching Tesla PowerPack Charging Status... ",'blue'))
    result(shodan_api_key,'''http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2''')
    print(colored(bold + "\n Fetching Electric Vehicle Chargers... ",'blue'))
    result(shodan_api_key,'"Server: gSOAP/2.8" "Content-Length: 583"')
    print(colored(bold + "\n Fetching Nordex Wind Turbine Farms... ",'blue'))
    result(shodan_api_key,'''http.title:"Nordex Control" "Windows 2000 5.0 x86" "Jetty/3.1 (JSP 1.1; Servlet 2.2; java 1.6.0_14)"''')
    print(colored(bold + "\n Fetching C4 Max Commercial Vehicle GPS Trackers ... ",'blue'))
    result(shodan_api_key,'"[1m[35mWelcome on console"')
    print(colored(bold + "\n Fetching DICOM Medical X-Ray Machines... ",'blue'))
    result(shodan_api_key,'"DICOM Server Response" port:104')
    print(colored(bold + "\n Fetching Electricity Meters... ",'blue'))
    result(shodan_api_key,'"Server: EIG Embedded Web Server" "200 Document follows"')
    print(colored(bold + "\n Fetching Siemens Industrial Automations... ",'blue'))
    result(shodan_api_key,'"Siemens, SIMATIC" port:161')
    print(colored(bold + "\n Fetching Siemens HVAC Controllers... ",'blue'))
    result(shodan_api_key,'"Server: Microsoft-WinCE" "Content-Length: 12581"')
    print(colored(bold + "\n Fetching Door / Lock Access Controllers... ",'blue'))
    result(shodan_api_key,'"HID VertX" port:4070')
    print(colored(bold + "\n Fetching Railroad Management... ",'blue'))
    result(shodan_api_key,'"log off" "select the appropriate"')
    print(colored(bold + "\n Fetching  Internet Connected Satellites... ",'blue'))
    result(shodan_api_key,'"Open Webif"')
    result(shodan_api_key,'("Cobham SATCOM") OR ("Sailor VSAT")')
    result(shodan_api_key,"Sailor VSAT")
    result(shodan_api_key,"Cobham SATCOM")
    print(colored(bold + "\n Fetching Internet Connected Submarine Dashboard ... ",'blue'))
    result(shodan_api_key,"Slocum Fleet Mission Control")
    print(colored(bold + "\n Fetching IOT Refrigeration Units ... ",'blue'))
    result(shodan_api_key,'"Server: CarelDataServer" "200 Document follows"')

def fetch_iot(shodan_api_key,bold):
    print(colored(bold + "\n Fetching IOT Video Conferencing Dashboards ... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,'"Polycom Command Shell" -failed port:23')
    print(colored(bold + "\n Fetching Internet Connected Media Players  ... ",'blue'))
    result(shodan_api_key,'"Server: Logitech Media Server" "200 OK"')
    print(colored(bold + "\n Fetching IOT Connected Home Devices ... ",'blue'))
    result(shodan_api_key,'"Server: AV_Receiver" "HTTP/1.1 406"')
    print(colored(bold + "\n Fetching IOT 3D Printer Controllers ... ",'blue'))
    result(shodan_api_key,'title:"OctoPrint"+-title:"Login"+http.favicon.hash:1307375944')

def fetch_vulnerable_servers(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Vulnerable Servers... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,"X-Jenkins+200+OK")
    print(colored(bold + "\n Fetching FTP Servers with Anonymous Login ... ",'blue'))
    result(shodan_api_key,' "220" "230 Login successful." port:21 ')
    print(colored(bold + "\n Fetching Vulnerable Samba Shares [ Network Attached Storage]... ",'blue'))
    result(shodan_api_key,'"Authentication: disabled" port:445')
    print(colored(bold + "\n Fetching Weave Scope Dashboards... ",'blue'))
    result(shodan_api_key,'title:"Weave Scope" http.favicon.hash:567176827')
    print(colored(bold + "\n Fetching MongoDB Sensitive Information ... ",'blue'))
    result(shodan_api_key,'"MongoDB Server Information" port:27017 -authentication')
    print(colored(bold + "\n Fetching Mongo Express Web GUI ",'blue'))
    result(shodan_api_key,'"Set-Cookie: mongo-express=" "200 OK"')
    print(colored(bold + "\n Fetching Docker APIs... ",'blue'))
    result(shodan_api_key,'"Docker Containers:" port:2375')
    print(colored(bold + "\n Fetching Docker Private Registries ... ",'blue'))
    result(shodan_api_key,'"Docker-Distribution-Api-Version: registry" "200 OK" -gitlab')
    print(colored(bold + "\n Already Logged-In as root via Telnet ... ",'blue'))
    result(shodan_api_key,'"root@" port:23 -login -password -name -Session')
    print(colored(bold + "\n Fetching Pi-hole Open DNS Servers... ",'blue'))
    result(shodan_api_key,'"dnsmasq-pi-hole" "Recursion: enabled"')
    print(colored(bold + "\n Fetching Android Root Bridges ... ",'blue'))
    result(shodan_api_key,'"Android Debug Bridge" "Device" port:5555')
    print(colored(bold + "\n Fetching Citrix Virtual Apps ... ",'blue'))
    result(shodan_api_key,'"Citrix Applications:" port:1604')
    print(colored(bold + "\n Fetching Cisco Smart Install ... ",'blue'))
    result(shodan_api_key,'"smart install client active"')
    print(colored(bold + "\n Fetching PBX IP Phone Gateways... ",'blue'))
    result(shodan_api_key,'PBX "gateway console" -password port:23')
    print(colored(bold + "\n Fetching Bomgar Help Desk Portal... ",'blue'))
    result(shodan_api_key,'PBX "gateway console" -password port:23')
    print(colored(bold + "\n Fetching Vulnerable domain controllers... ",'blue'))
    result(shodan_api_key,'"Authentication: disabled" NETLOGON SYSVOL -unix port:445')
    print(colored(bold + "\n Fetching Iomega / LenovoEMC NAS Drives... ",'blue'))
    result(shodan_api_key,'"Set-Cookie: iomega=" -"manage/login.html" -http.title:"Log In"')
    print(colored(bold + "\n Fetching Buffalo TeraStation NAS Drives... ",'blue'))
    result(shodan_api_key,'Redirecting sencha port:9000')
    print(colored(bold + "\n Fetching Etherium Miners... ",'blue'))
    result(shodan_api_key,'"ETH - Total speed"')
    print(colored(bold + "\n Fetching Apache Directory Listings... ",'blue'))
    result(shodan_api_key,'http.title:"Index of /" http.html:".pem"')
    print(colored(bold + "\n Fetching Misconfigured WordPress... ",'blue'))
    result(shodan_api_key,'http.html:"* The wp-config.php creation script uses this file"')
    print(colored(bold + "\n Fetching Minecraft Servers ... ",'blue'))
    result(shodan_api_key,'"Minecraft Server" "protocol 340" port:25565')


def fetch_remote_desktop(shodan_api_key,bold):
    print(bold + colored("\n Fetching Unauthenticated Remote Desktop Servers... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,"authentication disabled RFB 003.008")

    print(bold + colored("\n Fetching Windows RDP... \n",'blue'))
    result(shodan_api_key,'"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"')

    
def fetch_printers(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Online Printers... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,"Xerox Generic Root")
    result(shodan_api_key,'"Serial Number:" "Built:" "Server: HP HTTP"')
    result(shodan_api_key,'"SERVER: EPSON_Linux UPnP" "200 OK"')
 
def run_all(shodan_api_key,bold):
    fetch_internet_cameras(shodan_api_key,bold)
    fetch_ics(shodan_api_key,bold)
    fetch_iot(shodan_api_key,bold)
    fetch_vulnerable_servers(shodan_api_key,bold)
    fetch_remote_desktop(shodan_api_key,bold)
    fetch_printers(shodan_api_key,bold)

def custom_search_query(shodan_api_key,bold):
    try:
        query = str(input(colored(bold + "\n Enter your Query: ", 'yellow')))
        number_query = int(input(colored(bold +"\n Enter the number of results you need: ", 'yellow')))
        if number_query <=0:
            print(colored(bold + "\n Error: The minimum number of results should be at least 1. Please try again with a valid number.\n", 'red'))
            sys.exit(1)
        else:
            print(colored(bold + "\n Fetching " + query + " Please Wait... \n ", 'blue'))
            for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m', '\x1b[0m')):
                time.sleep(2)
                results = shodan_api_key.search(query, limit=number_query)
            if not results or 'matches' not in results or not results['matches']:
                print(colored(bold + " \n No Results Found\n ", 'red'))
                time.sleep(2)
            else:
                for resultMatch in results['matches']:
                    time.sleep(1)
                    print("\n")
                    print(colored("IP:", 'yellow') + f" {resultMatch['ip_str']}")
                    print(colored("Port:", 'yellow') + f" {resultMatch['port']}")
                    print(colored("Organization:", 'yellow') + f" {resultMatch.get('org', 'N/A')}")
                    print(colored("ISP:", 'yellow') + f" {resultMatch.get('isp', 'N/A')}")
                    print('')
                    time.sleep(2)
    except Exception as e:
        print(colored(f"\n An unexpected error occurred: {str(e)}\n", 'red'))
        exit()

def get_Options(shodan_api_key,bold):
    print(colored("\nSelect Choice \n",'green'))
    print("1. Internet Cameras")
    print("2. Scada System / Industrial Control Systems")
    print("3. IOT Ecosystsem / Home Devices")
    print("4. Exposed Server")
    print("5. Remote Desktop")
    print("6. Printers & Copiers")
    print("7. Run All of the Above")
    print("8. Custom Search Query")
    print("9. Exit")

    print("\n ==> Enter your Choice (1-9) ")
    option_input=(int(input()))
    if option_input <=0 or option_input>9 :
        print(colored(bold + "\n Invalid Input !!!!!  ",'red'))
        print(colored(bold + "\n Select Options Between  (1-9)",'yellow'))
        time.sleep(1)
        get_Options(shodan_api_key,bold)
    else:
        if option_input == 1:
            fetch_internet_cameras(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool! ", 'green'))
        if option_input == 2:
            fetch_ics(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
        if option_input == 3:
            fetch_iot(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
        if option_input == 4:
            fetch_vulnerable_servers(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
        if option_input == 5:
            fetch_remote_desktop(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
        if option_input == 6:
            fetch_printers(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
        if option_input == 7:
            run_all(shodan_api_key,bold)
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
        if option_input == 8:
            custom_search_query(shodan_api_key,bold)
            get_Options(shodan_api_key,bold)
        if option_input == 9:
            print(colored(bold + "\n Thanks for using our tool!", 'green'))
            exit()
    
def get_banner(shodan_api_key,bold):
    print("\n\n\n")
    colored_banner= '''

     $$$$$$\  $$\                       $$\                     $$\   $$\            $$\     
$$  __$$\ $$ |                      $$ |                    $$$\  $$ |           $$ |    
$$ /  \__|$$$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\  $$$$$$$\  $$$$\ $$ | $$$$$$\ $$$$$$\   
\$$$$$$\  $$  __$$\ $$  __$$\ $$  __$$ | \____$$\ $$  __$$\ $$ $$\$$ |$$  __$$\\_$$  _|  
 \____$$\ $$ |  $$ |$$ /  $$ |$$ /  $$ | $$$$$$$ |$$ |  $$ |$$ \$$$$ |$$$$$$$$ | $$ |    
$$\   $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$  __$$ |$$ |  $$ |$$ |\$$$ |$$   ____| $$ |$$\ 
\$$$$$$  |$$ |  $$ |\$$$$$$  |\$$$$$$$ |\$$$$$$$ |$$ |  $$ |$$ | \$$ |\$$$$$$$\  \$$$$  |
 \______/ \__|  \__| \______/  \_______| \_______|\__|  \__|\__|  \__| \_______|  \____/ 
                                                                                         
                                                                                         
                                                                                         
                                                                 Author: Ashutosh Mishra
    '''
    print(colored_banner)
    get_Options(shodan_api_key,bold)

def api_check(bold):
    if len(sys.argv) > 1:
        SHODAN_API_KEY=sys.argv[1]
        print(colored(bold + "\n Checking your API Key! \n ", 'green'))
        response=requests.get("https://api.shodan.io/account/profile?key="+SHODAN_API_KEY)
        if response.status_code == 200:
            shodan_api_key = shodan.Shodan(SHODAN_API_KEY)
            get_banner(shodan_api_key,bold)
        else:
            print(colored(bold + "\n Invalid Api Key Please Try Again !....\n ", 'red'))
            exit()
    else:
        usage_message = """Usage: python3 shodan_net.py <your_api_key>"""
        print(colored(bold + "\nPlease Pass your Api Key !....\n ", 'red'))
        print(colored(bold+usage_message, 'green'))

def main():
    bold = '\x1b[1m'
    api_check(bold)

if __name__ == "__main__":
    main()
