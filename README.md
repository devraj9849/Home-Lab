# Home-Lab

Detection Lab
 
Figure 1 Network Diagram
<h1>Part1: Installing pfsense firewall</h1>
For this lab first installing pfsense in the VMware workstation pro. Go to the link

    https://archive.org/details/pfSense-CE-2.6.0-RELEASE-amd64
 
Go to Edit>Virtual Network Editor >Change Settings>Add Network.
In VMnet0 type bridged add Microsoft Wifi Direct Virtual Adapter in case of Automatic.After this click Apply.
 
In our network adapter in case of bridged adapter place it under VMnet0.Furthermore, create a new network adapter and place it under NAT.
 
Run the pfsense machine.
 
After installation is completed it will show as the screenshot below
 
 
For now, pfsense is installed and we are going to setup the active directory.
Part2: Setting up Active Directory
We have taken windows server 2019 as a server for setting up the active directory.
https://info.microsoft.com/ww-landing-windows-server-2019.html
Similar to pfsense, keep on feeling details and I have name this as ADDC01.
 
 
It will take some time to install. After some time, it will tell you to enter password for the Administrator account. Then installation of windows 2019 is complete.
 
The first thing we are doing here is changing the computer name. 
Go to PC > Properties > Rename your PC in search and change it to ADDC01.
 
After this it will tell you to restart the system.
The next thing we want to do is assign a static IP address. 
Open Network and Internet Settings > change adapter settings > Ethernet0 > Properties >IPV4 and click on Use the following IP Address.
 
After this going to the command prompt and typing the command
ping 192.168.1.1
 
Now we can install Active Directory. 
Go to Server Manager > Manage > Add Roles and Features
 
This is the reason we changed everything on the above process. 
Click on Next and Select Role-based or feature-based installation.
 
After this click on Next and Select Server Roles. Select Active Directory Domain Services and click next.
 
Click on Install.
 
After installation is complete, click on promote this server to a domain controller.   
Then click on Add a new forest and devraj.local as root domain name and click next.
 
After this enter password and others you can keep it as default.
 
Then click Next until you see install.
 
Then it will restart the machine.
Now we can add some users into the system. Go to Search > Active Directory Users and Computers > devraj.local > Users
 
Instead of creating users into the Users tab, Right click into the Devraj.local > New > Organizational Unit
 
Here we are creating the organizational unit on the basis of IT, finance, and Sales.
Right Click on the organizational unit we just created and select New > User and add the users there. 
 
Now open windows 10 machine which we have already installed earlier.
 
After this Click on search > My PC > Rename this PC (advanced) > Change > Domain and enter our Active directory name which is Devraj.local. However it presented an error.
 
Here we have to make sure that the IP address of the windows 10 is in the same order as that of pfsense and ADDC01. For the windows 10 machine we have to keep the IP address static.
 
Making sure that the changes we made in making IP static is working or not.
 
From this we know that from windows 10 we can ping both the pfsense and domain controller however from domain controller we cannot ping windows 10. Here adding Devraj.local which is the domain name of active directory ADDC01. 
 
After this it will display 
 
And the system will restart.
We want to make sure that now the domain controller user that we made should be able to login in the windows 10 machine.
 
Here steven is the user we created in the active directory. Now we can log into the windows 10 using domain devraj.local of the active directory ADDC01.



Part3: Configuring Logging Policies
For this go to search > Group Policy Management > Forest > Domains > devraj.local
Right click on it and click Create a GPO in this domain, And Link it here.
 
For the name I have created Audit Policy – Endpoint and click ok.
After this right click on Audit Policy – Endpoint which we just created and click edit. Then go to Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies 
 
According to the Microsoft recommendation for baseline validation
1)	Account Logon
•	Audit Credential Validation – Success
 
2)	Account Management
•	Audit Computer Account Management – Success
•	Audit Other Account Management Events – Success
•	Audit Security Group Management – Success
•	Audit User Account Management – Success
 
3)	Detailed Tracking
•	Audit Process Creation – Success
 
4)	Logon/Logoff
•	Audit Logoff – Success
•	Audit Logon – Success, Failure
•	Audit Special Logon – Success
 
5)	Policy Change
•	Audit Audit Policy Change – Success, Failure
•	Audit Authentication Policy – Success
 
6)	System
•	Audit IPsec Driver – Success, Failure
•	Audit Security State Change – Success, Failure
•	Audit Security System Extension – Success, Failure
•	Audit System Integrity – Success, Failure
 
7)	After this click on Administrative Templates > System > Audit Process Creation > Include command line in process creation events. We are enabling this because when we enable Event ID 4688 which is process creation it will not show process command line which is vital for finding out which process was carried out.
 
8)	Click on Administrative Template > Windows Components > Windows PowerShell > Turn on PowerShell Logging and enable it. This is for Event ID 4104.
 
9)	Finally, we should also enable Audit: Force audit policy subcategory settings.
 
 For checking out everything we change is working or not. Go to Windows 10 machine and run with steven user.
Open Event Viewer as Administrator. And filter for Event ID 4688 under Security.
 
Looking out we were not able to see command line.
Now we are going to install and configure Sysmon to provide additional telemetry. In many environments, Sysmon or even EDR wouldn’t be available. This is why we have to know to enable proper logging on our machines to provide us with the telemetry to helps us with the investigation. Default settings in Sysmon is not enough.  
Download Sysmon.
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
It is a zip file so extracting the files.
Also go to the URL:
https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml and save the file and place it with Sysmon extracted file.
 

After this opening the PowerShell in administrator we get:
 
Click Agree. And it will get installed. Open Event Viewer in administrator and see whether Sysmon is installed or not. Go to Application and Services Logs > Microsoft > Windows > sysmon
 
And also, on Services we can see it is running.
 
For configuring logging policies this is the final step. Now we are goint to Part 4 which is setting up Splunk.
Part4: Setting up Splunk
For this we have already installed splunk. {later needed to be added about the installation of splunk}

 
IP address of Splunk = 192.168.132.130
We know that this is not in our detection lab network. So we should assign a static IP Address.
Command: sudo vi /etc/netplan/00-installer-config.yaml 
                   sudo netplan apply
 
 

 Our static IP address is 192.168.1.20
 
Now we are able to ping our firewall.
 
After the completion of above process, we can now open Splunk in windows 10 machine. Type:
192.168.1.20:8000
 

First, I will create a new index. For this go to Settings > Indexes > New Index.
 
Click Save. 
In windows 10, we want to share our data to Splunk. For this purpose, we would be installing a universal forwarder.
First download the universal forwarder from the Splunk website.
And also go to:
https://github.com/MyDFIR/Active-Directory-Project
and copy the contents of Readme file and name it as inputs.conf and save it as All Files.
After this run the universal forwarder we just downloaded.
 
Click on Next. For the username I added admin as the username. We do not have deployment server so we just click Next. But we have receiver index and we put the IP address of Splunk there.
 
After the installation is done. Click on Splunk and go to Settings > Forwarding and Receiving > Configure Receiving > New Receiving Port and add 9997.
 
After the installation of Splunk universal forwarder is complete go to the folder 
C:\Program Files\SplunkUniversalForwarder\etc\system\local and copy the inputs.conf file we added from the GitHub to this location.
 
Right click on inputs.conf file. And make the changes as seen in the screenshot below and save it.
 
Open Services as administrator and Splunk Forwarder > Log On> select Local System Account. Restart the Splunk Forwarder services.
 
After the completion of above process, we can run the query in Splunk.
index=mydfir-detect
 
Now our Splunk is able to get the data from windows 10. Now next thing to do is configuring the domain controller.
Performing the same thing that we did into the windows 10 to our Domain Controller. One of the easiest ways for sending our important file like universal downloader, Sysmon, inputs.conf is to create a network share. and also make sure that network discovery is turned on.
In windows 10:
 
And in Domain controller, 
 
After this copy the files into the system.
Now perform everything we did into the windows 10 like installing Sysmon, Splunk universal forwarder and also placing the input.conf file into its destination. After everything on Active Directory is done, then on splunk we can see whether we have two hosts there or not.
 
Part 5: Configure Zeek and Suricata
For Zeek and Suricata virtual machine, I will install an ubuntu machine with its name zeekandsuricata.
Opening Zeek and Suricata from our virtual machine. 
IP Address of zeek_suricata = 192.168.132.138
 
After this opening the system in putty or mobaxterm.
 
After this we are going to install zeek. Our ubuntu version is 22.0.4. Go to the website and select your ubuntu version and install it.
https://github.com/zeek/zeek/wiki/Binary-Packages
Mine is 22.04
•	echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
•	curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
•	sudo apt update
•	sudo apt install [zeek, zeek-6.0, or zeek-nightly]
 
Zeek is located under the following directory
cd /opt/zeek/bin
To customize zeek it uses the configuration file that is located under the above directory.
sudo vi /opt/zeek/share/zeek/site/local.zeek
 
Add these two lines in the bottom of the page
 
After this our configuration file should be updated with our ja3 and ja4 hashes. 
Now we are going to install JA3 and JA4 for zeek.
Setup JA3 for zeek:
sudo apt install zkg
zkg install ja3
Edit the local.zeek config in /opt/zeek/share/zeek/site/local.zeek and add in @load ja3
 
Setup JA4 for zeek:
zkg install zeek/foxio/ja4
 
Change the local.zeek config in /opt/zeek/share/zeek/site/local.zeek and add in @load ja4plus
 
This is the main file for the installation of zeek in the virtual machine.
Now we are going to install Suricata which is the IDS Intrusion Detection System.
Add Silver C2 rules for Suricata
sudo apt -y install libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0 jq
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt install suricata
sudo systemctl enable suricata.service
sudo systemctl stop suricata.service

We want to configure yaml file for its configuration file on Suricata. And this is located under the directory. And make sure that the community-id is set to true.
sudo vi /etc/suricata/suricata.yaml 
 
Suricata Rules
sudo suricata-update
sudo suricata-update - Update Rules
sudo suricata-update list-sources
sudo suricata-update enable-source tgreen/hunting
sudo suricata-update enable-source et/open
sudo suricata-update - Update Rules
sudo systemctl start suricata.service
sudo suricata -T -c /etc/suricata/suricata.yaml -v - Validating Suricata
/var/lib/suricata/rules/ - Rule Location
 
Immersive Labs
wget https://raw.githubusercontent.com/Immersive-Labs-Sec/SliverC2-Forensics/main/Rules/sliver.snort
After all this process completed, type
ip a
 
We know that this is not in our detection lab network. So, we are assigning a static IP Address.
Command: sudo vi /etc/netplan/00-installer-config.yaml 
                   sudo netplan apply
 
After this we can ping to our splunk server and we can ping it perfect.
 
Go to the splunk website and copy wget link for universal forwarder for sending data from zeek_suricata to the splunk.
 
Since the URL is too long we can use it a service called tinyurl. Just copy the link in tinyurl and shorten URL there.
 
Then in our virtual machine we can write:
sudo wget https://tinyurl.com/mydfir-detect12
 
After this we are going to install the deb file.
sudo dpkg -i mydfir-detect321
 
 
Here looking at the above screenshot we know it is owned by username splunkfwd. We are going to change into it.
sudo -u splunkfwd bash
./splunk start
 
It will tell you to enter username and password. And make sure that your splunk is enabled.
 
Now we have to point our zeek-suricata server to splunk server. For this
sudo ./splunk add forward-server 192.168.1.20:9997
sudo ./splunk list forward-server
 
The second command is used in order to make sure the changes we made using above command is working or not. Now we can go into the user splunkfwd and start the splunk. However we have active forwards to none.
sudo -u splunkfwd bash
./splunk start
 
we can see active forwards changed after writing the command below:
./splunk list forward-server
 
This is how we configure Splunk on our zeek-server to point our data over to the Splunk server. Now we need to configure our inputs.conf file, which will be responsible for sending all of the Zeek logs over to our Splunk and to do that first I will exit out and create an inputs.conf file under the etc/system/local for Splunk. So, writing the command:
sudo vi /opt/splunkforwarder/etc/system/local/
 
Now we need to got to 
cd /opt/zeek
cd logs 
however, we get permission denied.
So changing the user to root.
sudo su
 
After this finally we can go to the logs directory.
 
Furthermore, I need to change my network to promiscuous mode. In promiscuous mode, the NIC allows all frames through, so even frames intended for all other machines or network devices can be read. We recall that Zeek and Suricata is there to listen in on traffic, so that is why we need to have our network adapter or network interface card set to promiscuous mode.
sudo ip link set ens33 promisc on
 
After all these configurations we made, we want to make sure that Zeek and Suricata are running properly. 
 
We make changes to the host=192.168.1.30 and interface=ens33
 
After we make these changes we are going to deploy it by using the command:
sudo /opt/zeek/bin/zeekctl deploy
 
 

 
Inside of current folder we can see a lot of logs like conn.log, ssl.log, known_hosts.log and many more.
 
Now zeek is good to go. Shifting towards Suricata, its logs are found in 
cd /etc/Suricata
sudo vi Suricata.yaml
      
 Here in the suricata.yaml file change the eth0 to ens33. There are 3 interfaces having eth0. So change it to ens33.
 
After this run
systemctl restart suricata.service
 
In Suricata logs are stored in /var/log/suricata/
 
Running the command and making changes to inputs.conf file.
 
 
We are gonna make changes in the local.zeek file in order to making sure that the sourcetype file we get will be in json format.
 
 
After that we run the command
sudo /opt/zeek/bin/zeekctl deploy
 
Now zeek should start outputting its logs in json format. Now we have successfully configured our zeek and making changes for Suricata. Going to inputs.conf file again.
 
After this 
Sudo -u splunkfwd bash
Cd /opt/splunkforwarder/bin
./splunk stop
./splunk start
Now when we head to the windows machine we should be able to see some logs of zeek.
 
Part6: Configure PFSense
For pfsense, opening the pfsense in the windows 10 in browser.
 
Default username and password for pfsense is admin and pfsense respectively.
Click on Next.
Make sure this is checked off.
 
What I want to do with pfsense is that sending syslog over to our Splunk server and install SquidProxy. That way we can take a look at any proxy logs and then forward those proxy logs over to our Splunk server.
First I want to install SquidProxy before sending syslog over to our Splunk server. To install our proxy, go to System>Package Manager > Available Packages and search squid.
 
 
Then going to pfsense in virtual machine. Enter 8 to shell. Here we are installing Splunk universal forwarder similar to what we did into the windows machine. Going to Splunk universal forwarder and copying the URL. For pfsense it uses Free BSD.
 
Then going to tinyurl.com and shortening the URL.
 
Pfsense uses fetch instead of wget.
fetch https://tinyurl.com/mydfir-detect2
 
Then we are going to extract the file using the command below which will create a folder splunkforwarder.
tar xvzf mydfir-detect2
 
 
 
Let’s create an inputs.conf file
cd ..
cd /etc/system/local
ls
vi inputs.conf
 
 
Now we need to restart our splunk
Cd ../../../bin
./splunk stop
./splunk start
After this we can see logs of pfsense in the Splunk. Here we can see logs of pfsense are not parsed properly. For that we can install an application called ta-pfcents.
 


Part7: Generating Telemetry
Installing the kali linux in the vmware workstation. 
https://www.kali.org/get-kali/#kali-virtual-machines
 
The IP address is not in the range of our lab. So we are going to change the IP Address to static.
Go to Settings>Advanced Network Configuration>Wired Connection 1> IPV4 settings and set the method to manual.
 
Now the IP is changed to 192.168.1.250
 
So now I am going to create a basic malware to allow my windows machine to execute it, which will then establish a C2 connection back to my kali machine. For that I will be using msvenom.
 
The only reason we are doing this so that we can additional telemetry on the windows 10 machine, so that we can see that it in Splunk. Now opening msfconsole which is the Metasploit Framework console.
 
 
Then type exploit and here we are listening to that port
 
Opening the another tab on terminal.
python -m http.server 9999
Now going to windows 10 machine and typing 192.168.1.250:9999 in browser we get Invoices.docx.exe file. Make sure to disable windows defender. Now download the file.
 
Download this file and run it and head back to the kali machine. Meterpreter session is started.
 
Now we can do anything as we have full control of windows 10 machine. For this I am going to download desktop.ini file in Desktop of Kali from windows 10.
 
Furthermore performing nmap scan to create more telemetry.
 
Now when seeing in our splunk we can see every event that happened.
 
