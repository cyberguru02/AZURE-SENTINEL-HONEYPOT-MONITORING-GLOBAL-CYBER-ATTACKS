# AZURE-SENTINEL-HONEYPOT-MONITORING-GLOBAL-CYBER-ATTACKS

## Objective
This honeypot project is dedicated to creating an environment for simulating and monitoring cyber attacks worldwide. The main goal is to deploy Azure Sentinel as a cloud-based Security Information and Event Management (SIEM) system and configure a virtual machine as a honeypot. By intentionally exposing vulnerabilities, we simulate real-world cyber attacks originating from diverse global locations. This project offers practical insights into configuring Azure services, analyzing log data, and visualizing attack patterns using Azure's tools. This allows hands-on experience in cybersecurity operations and SIEM functionalities while enhancing skills in threat monitoring and defense strategies against cyber threats.

### Skills Learned

Understanding of cloud-based Security Information and Event Management (SIEM) systems, specifically Azure Sentinel.

Proficiency in setting up and configuring virtual machines (VMs) in cloud environments.

Ability to configure network security groups (NSGs) and manage firewall rules for VMs.

Hands-on experience in ingesting and transforming logs using Azure Log Analytics.

Knowledge of PowerShell scripting for log data transformation and integration with third-party APIs.

Familiarity with visualizing attack data geographically using Azure Sentinel.

### Tools Used
Azure Sentinel: Cloud-native SIEM for log ingestion, detection, and visualization.

Azure Virtual Machines: Used as honeypots for simulating cyber attacks.

Azure Log Analytics: Repository for storing and analyzing log data from VMs.

PowerShell: Scripting language used to extract and process log data for geographical visualization.

Third-party APIs: Used to derive geolocation data from IP addresses.

## Steps
Hey readers! I’ll be walking through how I utilized Azure Sentinel, Microsoft’s cloud-based Security Information and Event Management (SIEM) solution, while in addition to a deliberately open virtual computer set up as a honeypot. The objective is to actively monitor and log cyberattacks based on coming from different IP addresses located all over the world, and to showcase the collected data on a global map. 

 

                                                 He’s a broad view of the simulated network I created: 

 ![image](https://github.com/user-attachments/assets/52351a30-4d66-442e-b180-fbe9ebb9545c)



**Step 1: Sign up for Azure and Create a Virtual Machine**

 

I realized that I didn’t have to worry about having to pay for a subscription service, since a lot of platforms that provide virtual machines (VMs) often give free credit or trials to let users try out their services such as Amazon Workspace (AWS), Digital Ocean, IBM Cloud, and many other platforms! 

 

 
![image](https://github.com/user-attachments/assets/fe3d0b68-42a9-4e2e-bfba-b1a8be468d9b)


​

Once I created my account, I headed over to the Azure portal quickstart page and looked up for “virtual machine” within the search bar


 

​![image](https://github.com/user-attachments/assets/a21da50d-dc43-4757-98a0-1d5c0101f127)


 

 

And begin setting up the VM to become the front-facing network machine, exposed to the internet, that would become my honeypot, which would allow global attempts in infiltrating the VM. I configured my VM based on these personal settings: 

​

This is for the initial creation of the VM, then skip over the disks tab, and onto the network tab

 

![image](https://github.com/user-attachments/assets/2210d62e-a3c6-469d-a437-d4ed4b33f7af)



 

Create your username and password for the VM

 ![image](https://github.com/user-attachments/assets/bf76b022-cd27-4944-a017-165e783d58d9)



Once your VM is created make sure to create a network security group for the VM to be under in order to establish a baseline rule on how it’s allowed to be communicated.

​
![image](https://github.com/user-attachments/assets/6f013c30-8289-49d5-98b2-3a09c118d28a)

​

Having set an "any” firewall rule allows any traffic from anywhere. This is the configuration for making the VM discoverable for inbound attack attempts. To serve its purpose as a honeypot, we are making it easily discoverable and enticing for attackers which would allow me to gain better insight into these attackers as well as giving me the opportunity to gain practical technical knowledge and skills with SIEM technologies.


**Step 2: Create Log Analytics workspace**

 

Our primary goal is to develop a robust infrastructure for log management and analysis. We begin by creating a Log Analytics Workspace, which will serve as the central repository for our logs. This is to help ingest logs into our virtual machine.  This workspace forms the backbone of our SIEM tool, Azure Sentinel, enabling us to visualize geographic data on a map for enhanced threat intelligence. Doing so will collect Windows Event Logs and create a custom log that includes geographic information to identify the sources of these attacks. Next, we configure Microsoft Defender for Cloud to collect VM logs and route them to the Log Analytics Workspace, ensuring thorough data capture. Finally, we establish a connection between the workspace and our VM to enhance threat detection capabilities.

 
 
![image](https://github.com/user-attachments/assets/1255fcb8-7f7d-431f-8da7-05738e990c48)



**Step 3: Enable gathering VM logs in Security**

 

Our next step is to head to Microsoft Defender for Cloud, formerly known as Security Center, in order to support an integral step for creating the capability to aggregate logs from the VM and allocate it into the “Logs Analytics workspace” .

 
![image](https://github.com/user-attachments/assets/6644e654-65a1-4040-88a1-cfdf4209933c)

 

Under the Defender plans, turn off the SQL servers since we are not concerned with SQL-related processes and then press the save button to finalize the decision.


​![image](https://github.com/user-attachments/assets/36bf6347-32ce-4619-b990-b446a0200135)

​​

Next head over to the Data Collection tab on the right pane, and select the option to collect all types of events as well. 

​
![image](https://github.com/user-attachments/assets/9304c0ac-c5cd-4e8a-81c4-70665366744b)

​

Go ahead and connect back to the Log Analytics workspace and press on the created virtual machine and then press the connect button on the upper pane of the VM.

 

 ![image](https://github.com/user-attachments/assets/3c44a264-bb65-4321-914c-35b35f2b0df2)


 
![image](https://github.com/user-attachments/assets/785f4d0f-beae-44c6-bece-4e3e7964a673)

 
I then opened Azure in a new tab and went ahead to set up Sentinel by searching, then adding the VM to the Microsoft Sentinel workspace. By adding our VM to the Sentinel workspace it will be used to help display event logs and data.

​
![image](https://github.com/user-attachments/assets/de04afe0-c8b1-48a6-8dd9-ef3593fccb61)


**Step 4A: Configuring and Optimizing Microsoft Sentinel for Attack Data Visualization**


In setting up Azure Sentinel, we optimize the configuration of Microsoft Sentinel, our SIEM tool, to effectively visualize attack data. We start by creating Microsoft Sentinel and integrating it into our workspace, centralizing log analytics for more efficient analysis. Our focus is on Event ID 4625, which tracks failed login attempts, and we use IP addresses to obtain geolocation data to identify the attackers' locations. This information is used to create a custom log, which is ingested into Azure's Log Analytics Workspace and Sentinel. By including Latitude, Longitude, and Country data, we can accurately plot the attackers on a map, enhancing threat detection.

 

To do make sure to head over to the created virtual machine and extract the value from the Public IP address field:


​![image](https://github.com/user-attachments/assets/9d22b887-5174-422f-8524-137d0d93ddd8)


Note: If you see a strike out in black or red, an ip address exists. The reason for striking is to protect the ip address from being compromised.

​

Search and open the “Remote Desktop Connection” application in windows and use the public ip address you gathered. 

![image](https://github.com/user-attachments/assets/ba7cab42-5d2f-4ea5-9069-1b1ff9194b60)


You are then prompted by a credentials page when attempting to connect to the public IP address which you’ll use the VM username and password created earlier, but before successfully connecting, make sure to enter invalid VM credentials to trigger the event ID 4625: 


![image](https://github.com/user-attachments/assets/b13d495d-f5c5-4b10-8271-5bd7c18fc43f)


 ![image](https://github.com/user-attachments/assets/1a0567da-7486-41cc-a70b-161951d95860)


 ![image](https://github.com/user-attachments/assets/38091e05-8ddd-4337-b93d-a9cbdd2dfdf3)



​

Great, you've remotely logged into the created VM!

 

 
![image](https://github.com/user-attachments/assets/922cc520-33af-4db4-bc23-0f7e38d76834)

 

Also, go ahead and check for the Event ID 4625 in the events viewer and look further into the log to analyze.

 

 ![image](https://github.com/user-attachments/assets/aabfcfd0-0b90-4f27-87d1-41a995dbeebd)

 

​

**Step 4B: Turn off firewall to make vm more susceptible to attack**

 

I also turn off the firewall within the Azure vm by stating the public and private profile firewall stature to OFF. In this step, we disable the Windows Firewall on our VM to enable faster internet discovery. By turning off the Firewall, we allow ICMP echo requests, which are crucial for internet connectivity and discovery. After verifying the connectivity issue with a timed-out ping, we proceed to disable the Firewall settings for Domain, Private, and Public Profiles. With echo requests now permitted, the ping successfully resumes, ensuring better accessibility for internet-based activities. To do this, we will open the Command Prompt on our computer (not the VM) and use the following command: `ping <IP from our Public IP Address> -t`.

 

​
![image](https://github.com/user-attachments/assets/5ae07fbe-0d97-40ce-a5ee-fc949092278e)

 

![image](https://github.com/user-attachments/assets/7d8554e2-47b6-48b0-b49f-32ad672a1406)

 

​

**Step 4C: Retrieve Powershell script: Script**
​
In this step, we download a crucial PowerShell script,"Custom_Security_Log_Exporter.ps1," from a trusted source, Josh Madakor, via GitHub. This script is essential for extracting geographic information from logs. After downloading it, we open Windows PowerShell ISE on the VM, create a new script, and paste the downloaded code. We save the script as "Log_Exporter" on the Desktop for easy access. Here is the link of the custom powershell script: https://github.com/Mxyiwa/SIEM-AzureSentinelLab/blob/main/Log%20Exporter.ps1

 

​![image](https://github.com/user-attachments/assets/b6df316d-036d-48c0-a8c0-277cd2539473)


​

 

Additionally, we obtain an API key from Geolocation.io to ensure access to geo data in the script. This key is inserted into the script to enable accurate geographic data extraction. By completing these actions, we ensure the script is ready to extract essential geo data from logs for further analysis. 

 
![image](https://github.com/user-attachments/assets/b654e00b-55fb-4b4e-a2c7-b433d4d86dc7)

 

​![image](https://github.com/user-attachments/assets/dba8ee9f-851a-4c64-87de-ff3f848f858e)
 
 
 
 
​
**Step 4D: Executing Script for Geo Data Retrieval from Attackers**
In this phase, we implement the script, from the github, to gather geographic data from potential attackers. The script runs continuously, scanning the security log for failed login attempts. When detected, it extracts the IP addresses and retrieves their geographic information. This data is logged into a new file stored at a designated location for easy access and analysis. By executing this script, we create a system that consistently monitors and records failed login attempts, enhancing our ability to track and identify threats based on their geographic location.

 

The PowerShell script scans the event logs for failed login attempts, extracting the associated IP addresses and geographic data. It then generates a new log file with this information, which is saved in the "ProgramData" directory on the VM/Remote Desktop (the file path is highlighted in the picture below).

 
![image](https://github.com/user-attachments/assets/27c2f2c4-b802-4238-901d-6e8b55438bde)

​

Which you will receive lines of geo information associated with IP addresses. 

​
![image](https://github.com/user-attachments/assets/f498dff2-e314-4a48-974e-b60bd274dcbe)

​
​
 

**Step 5: Creating and Extracting Custom Fields from Raw Log Data**
In this stage, we set up a custom log within the Log Analytics Workspace to incorporate specific log data, including geographic information, into our analytics platform. First, we navigate back to the Log Analytics Workspace on Azure and select our designated Honeypot. We then create a custom log tailored to our needs by copying the relevant logs from the VM and saving them in a new notepad file named "failed_rdp.log." Next, we specify the collection path for the log file and provide necessary details, such as the log name ("FAILED_RDP_WITH_GEO"). After creating the custom log, we wait for it to be fully processed. Once ready, the custom log entries become accessible within the Log Analytics Workspace, allowing for seamless integration and analysis of the specified log data. change pic below:

 
![image](https://github.com/user-attachments/assets/68efe5dd-ff46-4011-b216-76164f5cbd47)

 

 ![image](https://github.com/user-attachments/assets/a516302d-931e-4ee9-ada8-75128f106227)


 

Select the failed_rdp.log file for the “Sample” tab, and then skip over the “Record Delimiter” tab since it will contain records of failed logins. 

             

A list of failed login records in a notepad:

​

​![image](https://github.com/user-attachments/assets/84786a87-a6ea-4e33-9a43-537f2401941b)


​
​

I then selected the pathway C:\ProgramData\failed_rdp.log, which will be the location on the log in the VM.

 
![image](https://github.com/user-attachments/assets/5ee707d0-7b13-464f-8747-964f47c8804a)

 
 

​​

 

Then set the custom log name to your preference and then finalize it in step 6:

 
![image](https://github.com/user-attachments/assets/cf173368-cfe5-4e69-b11f-71ec70d337e1)

 

 

**Step 6: Extracting Fields from Raw Custom Log Data version**

This step focuses on extracting essential fields from raw custom log data to enhance the analytical capabilities of our Log Analytics Workspace. Initially, we utilize specific code, which can be found on our GitHub repository, to extract all relevant data from the logs. This process enables the creation of distinct fields such as latitude, longitude, username, and country. As a result, when reviewing the log file within our VM, these extracted fields will be clearly delineated, facilitating easier interpretation and analysis. Subsequently, we navigate to our Log Analytics Workspace to observe the organized data, now separated into tabs for improved visibility and accessibility. Additionally, we open a new tab to overview our Microsoft Sentinel, where incoming logs can be observed, indicating successful data extraction and integration.


 

Next, navigate to the Log Analytics Workspace on Azure. Select the workspace you created, then choose "Logs." Enter the custom log name in the search bar and click "Run" to display the geodata from the log file.

 

 
![image](https://github.com/user-attachments/assets/302decbf-e7ea-437d-90f2-de2faa69a93a)


Regrettably, Microsoft has discontinued the feature for extracting fields from the data. As an alternative solution found online, the workaround involves embedding the custom script provided below into the workbook which we run it and view the failed login geodata of attackers.



Copy and paste the query from the GitHub repository (Log Analytics workspace Logs Query) into the workspace query field. We also want to change settings such as the visualization config to “Map” and Size: “Full” , and the Metric Settings as well. 

 ![image](https://github.com/user-attachments/assets/6dca4465-88b7-4105-b9a8-4172eaee422a)


Here are the results: 

![image](https://github.com/user-attachments/assets/0657a92e-53fe-42da-a4fe-aa948f645801)


Final stage: Creating the Attack Map using Geographic Data in Sentinel 
This last stage involves setting up a map visualization within Microsoft Sentinel to plot geographic data using latitude and longitude coordinates or country information. Initially, we created a workbook within Sentinel to organize and display our data effectively. Subsequently, we remove unnecessary widgets and execute a query by pasting previously used code. Upon running the query, we generate a visualization, selecting the map option to represent the geographic distribution of our data. The visualization provides valuable insights into the geographical origins of detected threats, enhancing our ability to analyze and respond to security incidents effectively.

 

After setting this up, we need to wait a few hours to observe the honeypot's discoverability. During this time, our query will remain active on Sentinel, continuously updating our map with detected attacks.

After being online for a few hours, our honeypot has encountered potential attacks originating from various countries, as depicted on our Sentinel map. As our VM remains connected, Sentinel will continuously update this map with new attacker data. Our VM script also continues to record failed login attempts from these attackers.

 

 
![image](https://github.com/user-attachments/assets/e1e3848c-1777-4947-a686-cc163f5fe3cf)

Attacker map after 10 hours

​

Key Takeaways
 

The Key takeaways I had with this project are:

This lab underscores the critical importance of cybersecurity. When accessing the internet via any platform, users are exposed to  cyber threats that can originate from anywhere in the world and must be vigilant. Best practices to retain vigilance includes regularly installing security updates, using strong passwords, enabling multi-factor authentication (MFA), and more. Whether accessing the internet through various applications/platforms or whatever other method, it's crucial to be aware of the potential exposure it poses to your device.

Learn the insides of how Azure Security Sentinel operates. By understanding its various capabilities and processes, I have better insight in how it empowers cybersecurity professionals to effectively enhance an organizational security measures.

My last takeaway is that the project showcased the implementation of robust cybersecurity measures and the effective utilization of honeypots. Utilizing honeypots improves my understanding of threat mitigation strategies in cybersecurity, providing valuable insights into how attackers operate and allowing for proactive defense measures.
