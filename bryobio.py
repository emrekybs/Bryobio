import os
import sys
import datetime
import dpkt as pc
import time
import dpkt
import socket
import pyshark
import tempfile
import re
import subprocess
from termcolor import colored

class colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

ascii = '''
               
───▌─▌─────▐─▐───
──█─█──▄─▄──█─█──
─█▀─▀▀▄▌▄▐▄▀▀─▀█─
▐▌─▄▀▄█████▄▀▄─▐▌
─▀▀─▄▄█████▄▄─▀▀─      🕸︎It was developed to speed up the processes of🕸︎
──▄▀─▄▀███▀▄─▀▄──              🕷️SOC Analysts during analysis🕷️
▄█─▄▀──███──▀▄─█▄
█──█───▐▀▌───█──█
█───█───────█───█
▀█──█───────█──█▀
─█───█─────█───█─
──▌──█─────█──▐──
──────▌───▐──────                  
                                                                                                                                  '''
print(ascii)
time.sleep(1)
print("𝔹ℝ𝕐𝕆𝔹𝕀𝔸🕷️STARTING!!")
time.sleep(1.4)
supported_info = '''
\n

🕸︎ 𝔹ℝ𝕐𝕆𝔹𝕀𝔸 🕸︎ 

(PCAP ANALYSIS TOOL)
E-MAIL--> emrekoybasi@protonmail.com
Github--> https://github.com/emrekybs
\n
'''
print(colored(supported_info, 'red'))


def configure():

	try:
		with open('/usr/share/wireshark/init.lua', 'r') as f:
			replace = []
			for line in f.readlines():
				replace.append(line.replace('disable_lua = false', 'disable_lua = true'))
		with open('/usr/share/wireshark/init.lua', 'w') as f:
			for line in replace:
				f.write(line)
	except:
		None

def check():
	configure()
	reads = (os.popen("tshark -h")).read()

	if 'WARNING' in reads:
		print(colors.BOLD + ("[+] Tshark found Lest Go !\n") + colors.END)
		configure()
		pass



check()

print(colors.BOLD + ("<--Let's Choose PCAP File-->") + colors.END)

def packet():

		pcap = input("Location Pcap File-# ")
		if pcap == pcap:
			control = (os.popen("file " '%s' %pcap)).read()
			if 'capture file' in control:
				print ("[+] Pcap File Selected Successfully\n")
				pass
			else:
				print(colors.RED + ("This file not Pcap\n Exit..") + colors.END)
				sys.exit()
		while True:

			print("\n")
			print(colors.RED + (" "*15+"<--🕸︎SPIDER WITH BRYOBIO🕸︎-->\n") + colors.END)
			print((" 1-Top 10 Visited Sites" + " " * 13 + "2-GET Emails\n"))
			print((" 3-Spider URLS" + " " *   15+ "4-User-Agents List\n"))
			print((" 5-String Mode" + " " *   15 + " 6-Connection details\n"))
			print((" 7-Ports Used" + " " * 23 + "8-Spider ALL Ip List\n"))
			print((" 9-Manuel Packet Filter" + " " * 13 + "10-Smtp Analysis\n"))
			print("                    11-Spider Web Attack "                         )


			pack = input(colors.RED + "\nChoose 🕸︎ #-> " + colors.END)
			print("\n")

			if pack == "1":
				top10 = os.popen("tshark -T fields -e http.host -r '%s' | sort | uniq -c | sort -nr" % pcap).read()
				print(colors.RED + ("Top 10 Visited Sites\n\nRequest | HOST") + colors.END)
				print (top10)

			elif pack == "2":
				print(colors.RED + ("Get Emails\n") + colors.END)
				print(colors.RED + ("[Warning!]There is a Possibility of Error(%80)\n") + colors.END)
				email = os.popen("ngrep -q -I '%s'" %pcap).read()
				reg = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b", email)

				st = set()
				uniq = [allmail for allmail in reg if allmail not in st and not st.add(allmail)]

				for onering in uniq:
					print (onering)


			elif pack == "3":

				contol = os.popen("file '%s'" % pcap).read()

				if "tcpdump" in contol:
					f = file(pcap, "rb")
					pcap2 = pc.pcap.Reader(f)
					pass
				else:
					print ("[Error!] Don't TcpDump File\n")
					print ("Converter 'tcpdump' format.Please Wait..\n")
					print ("--------------------------------")
					print ("Example : New.pcap")
					name = input("Please New File Name : ")
					print ("--------------------------------\n")
					tmp = tempfile.NamedTemporaryFile(delete=False)
					time.sleep(2)
					converter = os.popen("mergecap '%s' -w %s'%s' -F pcap" % (pcap,tmp.name, name))
					print(("[+]Create %s%s \n\nProcessing Please Wait...\n" % (tmp.name,name)))
					time.sleep(3)
					fin = (tmp.name+name)
					f = file(fin, 'rb')
					pcap2 = pc.pcap.Reader(f)

				def ips(inet):

					try:
						return socket.inet_ntop(socket.AF_INET, inet)
					except ValueError:
						return socket.inet_ntop(socket.AF_INET6, inet)

				for ts, nul in pcap2:
					adr = pc.ethernet.Ethernet(nul)

					ip = adr.data
					tcp = ip.data
					timestamp = time.time()

					try:

						if tcp.dport == 80 and len(tcp.data) > 0:
							try:
								http = pc.http.Request(tcp.data)
							except (pc.dpkt.UnpackError, AttributeError):
								continue


							if isinstance(ip.data, pc.tcp.TCP):

								print ("------------------------------------------------------------------------")
								print("Time           : ", str(datetime.datetime.utcfromtimestamp(timestamp)))
								print("HTPP Adress    : ", http.headers['host'])
								print("HTTP URI       : ", http.uri)
								print('Source         :  %s\nDestination    :  %s   NOTE :-> (Length=%d - TTL Value=%d)' % (
									ips(ip.src), ips(ip.dst), ip.len, ip.ttl))
								print("User-Agent     : ", http.headers['user-agent'])
								print("Modified Since : ", http.headers['if-modified-since'])

					except:
						pass

				print("\n")
				print(colors.RED+ "Alternative Output")

				request = os.popen("tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method == \"GET\"' -r '%s' | sort | uniq" %pcap).read()

				print ("----------------------------------------------------------")
				print(colors.RED + ("    Host             |               Request URI\n") + colors.END)
				print ("----------------------------------------------------------")
				print (request)
				print ("----------------------------------------------------------")


			elif pack == "4":
				userA = os.popen(
					"tshark -Y 'http contains \"User-Agent:\"' -T fields -e http.user_agent -r '%s' | sort | uniq -c | sort -nr" % pcap).read()
				print(colors.RED + ("How Many | User-Agent List\n") + colors.END)
				print (userA)


			elif pack == "5":

				stingr = input(colors.YELLOW + "Search String : " + colors.END)

				print(colors.RED + ("Results\n") + colors.END)
				response = subprocess.call("ngrep -q -I '%s' | grep -i '%s' | sort | uniq -c" % (pcap, stingr),
											shell=True)

			elif pack == "6":

				print ("\na- IO Statistics")
				print ("b- Protocol Tree")
				print ("c- Conversation Details(TCP,IP,UDP)")
				print ("d- All Conversation Details\n")

				itachi = input("\nWhich ? > ")

				if itachi == "a":
					io = subprocess.call("tshark -r '%s' -qz io,stat,10,tcp,udp,icmp,ip,smtp,smb,arp,browser" %pcap , shell=True)

				elif itachi == "b":
					prototree = subprocess.call("tshark -r '%s' -qz io,phs" %pcap, shell=True)

				elif itachi == "c": # Protocol if : else control Error..

					print(colors.RED + ("TCP Conversation\n") + colors.END)

					tcpt = subprocess.call("tshark -r '%s' -qz conv,tcp" % (pcap), shell=True)

					print(colors.RED + ("IP Conversation\n") + colors.END)

					ipt = subprocess.call("tshark -r '%s' -qz conv,ip" % (pcap), shell=True)

					print(colors.RED + ("UDP Conversation\n") + colors.END)

					udpt = subprocess.call("tshark -r '%s' -qz conv,udp" % (pcap), shell=True)

				elif itachi == "d":

					print(colors.RED + ("All Conversation Details\n") + colors.END)
					conver = pyshark.FileCapture('%s' %pcap)

					def conversat(converpack):
						try:

							proto     = converpack.transport_layer
							src_addr  = converpack.ip.src
							src_port  = converpack[converpack.transport_layer].srcport
							dst_addr  = converpack.ip.dst
							dst_port  = converpack[converpack.transport_layer].dstport
							print(("Protocol: " '%s' "  -  ""Source: " '%s'" - PORT: "'%s' " ----> " "Destination: " '%s'" - PORT: "'%s' %(proto,src_addr,src_port,dst_addr,dst_port)))

						except AttributeError:
							pass
					conver.apply_on_packets(conversat, timeout=50)


			elif pack == "7":

				print(colors.RED + "How Many | Port Used" + colors.END)

				port = subprocess.call("tcpdump -nn -r '%s' -p 'tcp or udp' | awk -F' ' '{print $5}' | awk -F'.' '{print $5}' | sed 's/:/ /g'  | sort | uniq -c | sort -n" %pcap, shell=True)

			elif pack == "8":

				print(colors.RED + "ALL IP List\n" + colors.END)

				ipls = os.popen("tcpdump -nn -r '%s' -p 'tcp or udp'" %pcap).read()
				ipreg = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", ipls)

				st2 = set()
				uniq2 = [allip for allip in ipreg if allip not in st2 and not st2.add(allip)]

				for sauron in uniq2:
					print((colors.YELLOW+"[+]"+colors.END+colors.BLUE +sauron+colors.END ))

				print("\n")

				print(colors.RED + "[+BONUS]Request IP List\n" + colors.END)

				reqipl = os.popen("tcpdump -nn -r '%s' -p 'tcp or udp' | awk -F' ' '{print $3}' | awk -F'.' '{print $1\".\"$2\".\"$3\".\"$4}' | sort | uniq | sort -n" %pcap).read()


				print((colors.BLUE+reqipl+colors.END))


			elif pack == "9":

				print(colors.YELLOW + "Manuel Packet Filter" + colors.END)
				print(colors.BLUE + "Filter Referance :\nhttps://www.wireshark.org/docs/dfref/\nhttps://wiki.wireshark.org/DisplayFilters\n" +colors.END)

				filt = input("Filter > ")

				try:
					filtr = pyshark.FileCapture(pcap, display_filter='%s' %filt)

					for tr in filtr:
						print (tr)
				except:
					return

			elif pack == "10":

				print(colors.RED + "SMTP Message Info\n" + colors.END)

				list_key = ['Date:', 'To:', 'Subject:', 'From:', 'X-Mailer', 'Pass','User']
				app_list = []
				smtp = file(pcap, "rb")

				for s in smtp:
					for word in list_key:
						if s.startswith(word):
							app_list.append(s)

				for list_ in app_list:
					print(colors.BLUE + (list_) + colors.END)

			elif pack == "11":

				sql = ['UNION', 'SELECT', 'CONCAT', 'FROM', 'union', 'select', '@@version', 'substring', 'information',
					   'table_name', 'from', 'convert', 'concat']
				xss = ['%3Cscript%3E', 'ALeRt', 'ScriPt', '<script>', '</script>', 'alert(\'xss\')', 'XSS', 'xss',
					   'alert(', '\';alert', 'onerror', 'document.cookie', 'onmouseover', '<img>', '<SCRIPT>',
					   'SCscriptIPT', 'scSCRIPTipt', 'onfocus=alert', 'alALERTert', 'String.fromCharCode']
				lfi = ['../../', '..//..//', '../', '/etc/passwd', '/etc/', '/proc/self/environ', '%00',
					   'php://filter/convert.base64-encode/resource=', 'cat /etc/passwd', 'system()', 'exec()',
					   'whoami']  # & Code Exec


				openpack = open(pcap)
				pcap11 = dpkt.pcap.Reader(openpack)
				app = []

				print((colors.YELLOW+"\nWEB Attack Detection\n\nInclude Modules:\n[+XSS]\n[+LFİ]\n[+SQLİ]\n"+colors.END))

				for ts, buf in pcap11:
					eth = dpkt.ethernet.Ethernet(buf)
					ip = eth.data
					tcp = ip.data

					try:

						if tcp.dport == 80 and len(tcp.data) > 0:
							http = dpkt.http.Request(tcp.data)
							asd = str(http.uri)
							tata = app.append(asd)

							for url in app:
								pass

							for vuln in sql:
								if vuln in url:
									try:
										print(colors.RED + "SQLİ Attack URL: " + colors.END, url)

									except:
										AttributeError

							for vuln2 in xss:
								if vuln2 in url:
									try:
										print(colors.BLUE + "XSS Attack URL: " + colors.END, url)
									except:
										AttributeError

							for vuln3 in lfi:
								if vuln3 in url:
									try:
										print(colors.YELLOW + "LFI Attack URL: " + colors.END, url)
									except:
										AttributeError

					except:
						AttributeError


try:
	if __name__ == '__main__':
		select = input("Continue By Pressing '0' To Use-# ")

		if select == "0":
			packet()

except:
	KeyboardInterrupt
	print ("Bryobia is closing..")			
