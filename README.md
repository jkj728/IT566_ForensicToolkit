# IT566 Digital Forensics Toolkit

## Introduction
lorem ipsum

formatting



## Suricata
|Section |  Information|
|--|--|
|Description | Suricata is a publicly available Intrusion Detection System and Intrusion Prevention System similar to Snort. Additionally, it can be used for network monitoring purposes. It is driven by signature detection enabled by Yara rules that can be run on Suricata’s multiple threads. Many consider Suricata to be a excellent resource for threat detection and prevention. |
|Personal Review | I used Suricata in the Digital Forensic Lab 4. In this lab I used Suricata in order to signature match a packet payload in pcap. Though the signature that matched was simply an HTTP request being sent to Google, the lab demonstrated the usefulness of Suricata in network monitoring. While the tool was quite helpful, cohesive documentation for Suricata usage seemed somewhat difficult to find. |
|Personal notes on Usage | <ul> <li>enabling Yara on a network interface: suricata -c /etc/suricata/suricata.yaml -i wlan0 </li><li> example Suricata rule: drop tcp $EXTERNAL_NET any -> $HOME_NET  (msg:"Block User Ports"; classtype:bad-unknown; sid:9900001; rev:1;) </li></ul>|
|Source | https://suricata-ids.org/download/ |

## Yara
|Section |  Information|
|--|--|
|Description | At its core, Yara is essentially a pattern matching engine. As such, Yara can be used by researchers, antivirus and IDSs alike in order to detect malware and react accordingly. Yara is build upon rules that are composed of strings that can be manipulated using modifiers and searched for using regular boolean logic operators. When a Yara rule is run against a file or string, it will return the rules that positively matched their respective patterns against the file/string. |
|Personal Review | Yara was a useful tool to see how signature matching worked at a low level implementation. Additionally, Yara was interesting in its computational efficiency relative to other tools in the industry: it is because Yara is so quick and included many different operators that it has become the de facto standard for the industry and has seen such widespread adoption. Additionally, I was able to work on enhancing the Yara framework for my group’s capstone project and added additional modifiers to the framework. |
|Personal notes on Usage | <ul> <li>using Yara: yara rule_file file to be searched</li><li>     example Yara rule:rule ExampleRule{    strings:        $my_text_string = "text here"        $my_hex_string = { E2 34 A1 C8 23 FB }   condition:        $my_text_string or $my_hex_string}</li></ul>|
|Source | https://github.com/VirusTotal/yara |

## GREP
|Section |  Information|
|--|--|
|Description | Grep is commonly known and used command line tool that is designed for searching text or files for a pattern. This pattern can be specified via a regular string or a regular expression. At its core, grep uses finite state machines designed by Ken Thompson to efficiently search for a regular expression. |
|Personal Review | I used grep in lab 4 to gain basic familiarity with pattern searching/matching and its relationship to finite state machines. I also frequently use grep on a daily basis while searching code repositories for strings that relate to my current projects at work. |
|Personal notes on Usage | <ul> <li>grep [OPTION]... PATTERN [FILE]...</li></ul>|
|Source | http://ftp.gnu.org/gnu/grep/  |

## BPF
|Section |  Information|
|--|--|
|Description | BPF stands for Berkeley Packet Filter and is most commonly used for network traffic analysis. BPF is used by programs like tcpdump in order to view and filter data link layer traffic as well as all data above layer 2 in the OSI model.  |
|Personal Review | The only time which I techincally use BPF was in creating a filter for tcpdump during lab 4. This was used in order to filter network traffic based on specific tcp or udp attributes in order to limit the copious amounts of traffic that were injested during a regular tcpdump packet collection. |
|Personal notes on Usage | <ul> <li>simple tcpdump filter example: tcpdump src 8.8.8.8</li></ul>|
|Source | https://elixir.bootlin.com/linux/latest/source/kernel/bpf/core.c |

## Write Blocker
|Section |  Information|
|--|--|
|Description | A write blocker is a hardware device that is specifically designed with purpose of blocking write operations to computer hard disks – AKA only allowing read operations. This kind of device is especially useful in Digital Forensics and incidence response in that it maintains the integrity of data stored on a drive such that said data can be considered valid and legitimate to be used in a courtroom. This is done by intercepting write commands from an operating system before they actually reach the hard drive itself. |
|Personal Review | A Tableau hard drive write blocker was used in conjunction with FTK imager in lab 6 in order to obtain a hard drive image and maintain its integrity during the digital forensics process. Although I am uncertain as to how “up to date” the hard drive write blocker was consdiering it used a firewire cable and a PS/2 connector, the device worked great for its purposes and it was nice to be able to take disk image without having to worry about affecting the hard drive’s data integrity. |
|Personal notes on Usage | <ul> <li>usage was relatively straightforward: corresponding PS2 and firewire cables needed to be connected as well as a hard drive cable to the HDD before the write blocker was switched to “on” and used to take an image.</li></ul>|
|Source | N/A |

## FTK Imager
|Section |  Information|
|--|--|
|Description | FTK Imager is a computer forensics tool used for data preview of imaging in order to acquire digital forensic data. This is done by importing an image file into FTK imager which then can use a variety of tool to assist you in your forensic examination. For example, FTK imager can be used to view contents of deleted file and well as group files by extension type and location in the local file system. |
|Personal Review | I used FTK Imager during the drive acquisition lab in conjunction with Autopsy in order to search for and document images and files related to potential money laundering. The program was incredibly useful in sorting data into categories that would be likely locations/culprits of forensic data like images and deleted files. |
|Personal notes on Usage | <ul> <li>the best possible advice for using FTK imager would be to view some simple documentation and then play around with the different tools it has</li></ul>|
|Source | https://accessdata.com/product-download/ftk-imager-version-4-2-1 |

## Autopsy
|Section |  Information|
|--|--|
|Description | Quite similar to FTK Imager, Autopsy is a computer forensic tool designed to be used for image analysis. Autopsy provides features such as intuitive data/file grouping, viewing of deleted/dereferenced files, advanced searching, hashing, etc. |
|Personal Review | Like FTK Imager, I used Autopsy during the drive acquisition lab in order to find files potentially related to money laundering. Autopsy was quite useful and its interface was similar to that of FTK Imager.  |
|Personal notes on Usage | <ul> <li>The best way to learn how to use autopsy was simply to play around with the user interface and familiarize myself with the different tools that it had available.</li></ul>|
|Source | https://www.autopsy.com/download/ |

## LiME
|Section |  Information|
|--|--|
|Description | LiME stands for Linux Memory Extractor and is a digital forensics and incidence response tool used for capturing volatile memory from an active Linux computer. Such functionality is very important in the first stages of digital forensics and incidence response. Given its functionality, LiME captures running processes, applications, services, network connections and more. |
|Personal Review | I used LiME in order to capture the physical memory of a device over netcat on the network acquisition lab for the class. However, after capturing the memory using LiME it was somewhat difficult to find an adequate program for performing analysis on the captured memory file. |
|Personal notes on Usage | <ul> <li>example usage with netcat: sudo insmod lime-4.9.0-8-amd64.ko "path=tcp:4444 format=lime timeout=0"</li></ul>|
|Source | https://github.com/504ensicsLabs/LiME |

## Netcat
|Section |  Information|
|--|--|
|Description | Netcat is an extremely popular and ubiquitous networking utility designed for simple reading and writing to network connections via common protocols such as TCP or UDP. As such, netcat is used it many programs for basic network connections. Additionally, netcat is very useful for digital forensic experts and hackers alike who seek to access computers remotely. |
|Personal Review | Netcat was the primary tool I used in the network acquisition lab in order to pipe command output and transfer files remotely over the network to my host computer. While netcat’s interface took a little bit of time to get used to, overall it was an extremely useful tool and its use was quite educational. |
|Personal notes on Usage | <ul> <li>listening on netcat: netcat -l 4444</li><li>sending files through netcat: netcat domain.com 4444 < original_file</li></ul>|
|Source | https://github.com/bonzini/netcat |

## Wireshark
|Section |  Information|
|--|--|
|Description | Wireshark is a widely used network packet analysis tool that be used to capture data or analyze existing capture files. Some wireshark features include: importing packey captures, searching for packets on various criteria, filtering traffic, reconstructing traffic streams, downloading files from streams, etc. |
|Personal Review | I used wireshark in the network analysis lab in order to search a traffic pcap file for potentially malicious activity. Wireshark’s interface was incredible useful in acquiring files that had been transferred in the traffic and also in isolating traffic by certain parameters/filters. |
|Personal notes on Usage | <ul> <li>how to filter by IP: ip.addr == 192.168. 1.199</li><li>how to filter by protocol: http</li></ul>|
|Source | https://code.wireshark.org/review/gitweb?p=wireshark.git;a=tree |

## Volatility
|Section |  Information|
|--|--|
|Description | Volatility is one of the most commonly used open source programs for physical memory analysis. Volatility supports a wide range of operating systems and also is kept up to date regularly according to the computing environment’s changes and needs. Using the program you can retrieve processes from memory, network connections, logs, etc. |
|Personal Review | I used volatility in the memory analysis lab in order to investigate a vmem capture file for malicious behavior and determine what forensic evidence I could glean. It was useful to determine kernel type, running processes, network connections and potential malware loaded into memory. |
|Personal notes on Usage | <ul> <li>determine kernel type: python ~/Src/volatility/vol.py -f ./lab.vmem imageinfo</li><li>determine running processes: ~/Src/volatility/vol.py -f ./lab.vmem --profile=WinXPSP2x86 psscan</li><li>determine network connections: python ~/Src/volatility/vol.py -f ./lab.vmem --profile=WinXPSP2x86 sockscan</li><li>locate possible malware: python ~/Src/volatility/vol.py -f ./lab.vmem --profile=WinXPSP2x86 malfind –dump-dir ./malware/</li></ul>|
|Source | https://github.com/volatilityfoundation/volatility |

## VirusTotal
|Section |  Information|
|--|--|
|Description | Virustotal is an online service that analyzes files and URLs for detection of malware or other malicious content using antivirus engines and databases. Acquired by Google, virustotal is a malware researcher, incident response team and digital forensic scientist’s best friend in determining if a particular file contained potentially malicious code that has been seen by the community at large. |
|Personal Review | I used VirusTotal extensively in labs like the networks analysis and memory analysis labs in order to test and validate that certain files or downloads were indeed malicious and also to provide a reputable source to back up my classification – also it was useful when I had no idea as to whether or no a file might be malicious. |
|Personal notes on Usage | <ul> <li>simply visit the VirusTotal website and choose a file to upload for analysis</li></ul>|
|Source | https://www.virustotal.com/gui/home/upload |

## OSXPMem
|Section |  Information|
|--|--|
|Description | OSXPMem is a memory acquisition tool designed for use with Mac OSX Systems. Similar to LiME or volatility, its purpose is to aid digital forensic investigators and incidence repsonse teams in their ability to collect volatile data from a computer. |
|Personal Review | While there was a lab designed around using OSXPMem to capture the physical memory from a device, there was an issue with running the program and we were unable to experiment with it. |
|Personal notes on Usage | N/A |
|Source | https://github.com/wrmsr/pmem/tree/master/OSXPMem |

## SIEM
|Section |  Information|
|--|--|
|Description | SIEM software stands for Security Information and Event Management software and provided security, application and networking professionals with insight into past and real time log data and analysis. SIEMs can also be configured to automatically alert individuals and teams under certain log conditions as well. |
|Personal Review | Though I did not use a SIEM in the Digital Forensics class this year, I stood up an ELK Stack in IT 366 and also use Splunk extensively at my current employment in order to monitor applications and maintain network security. On a whole, they have been incredibly insightful and useful when configured properly. |
|Personal notes on Usage | <ul> <li>depends on the SIEM being used</li></ul>|
|Source | N/A |

## Snort
|Section |  Information|
|--|--|
|Description | Similar to Suricata, Snort is a rule based intrusion prevention system IPS that is capable of real time traffic analysis and packet logging on a computer network. As such, it is extremely useful for security in helping perform traffic analysis and detecting a variety of potential cyber security attacks. |
|Personal Review | We setup Snort at one point during the semester simply to familiarize ourselves with the setup process; however, we did not have time to create any custom rules or to test them against actual network traffic. |
|Personal notes on Usage | N/A |
|Source | https://www.snort.org/downloads |

## Security Onion (Not Used)
|Section |  Information|
|--|--|
|Description | Security Onion is a widely used open source Linux distribution based around intrusion detection, SIEM monitoring and log management. Inside of the distribution are a variety of tools, including: elasticsearch, logstash, kibana, snort, suricata, bro, cyberchef, etc. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://github.com/Security-Onion-Solutions/security-onion |

## EnCase (Not Used)
|Section |  Information|
|--|--|
|Description | EnCase is an digital forensic investigation platform that is designed to collect digital data, perform analysis and generate reports in a court validated and forensically sound format. As such, it is extremely useful for digital forensics. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://www.guidancesoftware.com/encase-forensic |

## X-Ways (Not Used)
|Section |  Information|
|--|--|
|Description | In some ways similar to EnCase, X-Ways is a integrated digital forensics environment used for forensic analysis and data recovery. Some features included in X-Ways include: hard disk cleansing, binary data viewers, deleted files viewer, etc. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | http://www.x-ways.net/forensics/ |

## DEFT (Not Used)
|Section |  Information|
|--|--|
|Description | Deft stands for Digital Evidence & Forensics Toolkit; while its name is mostly self explanatory, Deft is a Linux distribution designed to perform digital forensic analysis on systems without tampering or corrupting devices such as captured data can still be considered admissible in court. Some features include: traffic acquisition tools, no swap partitions created on the system analyzed, not automated systems for any activity during the analysis of the evidence, etc. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://distrowatch.com/table.php?distribution=deft |

## Paladin (Not Used)
|Section |  Information|
|--|--|
|Description | Similar to the previous few tools, Paladin in a modified Linux distribution that has been outfitted with its own digital forensics analysis tools. Like the others, Paladin boasts using tools that are court tested and will not tamper with digital evidence in a way that will make it inadmissible in court. One of its built in features is Autopsy, mentioned earlier. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://sumuri.com/software/paladin/ |

## SANS SIFT (Not Used)
|Section |  Information|
|--|--|
|Description | The SANS SIFT workstation is a group of free open-source incident response and forensic tools designed to assist in digital forensic examinations. All tools in SIFT can be install on a Linux distribution. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://digital-forensics.sans.org/community/downloads |

## CAINE (Not Used)
|Section |  Information|
|--|--|
|Description | CAINE stands for Computer Aided Investigative Environment and like other tools is a Linux distribution designed to combine multiple digital forensics tools in one easy to access location. Some features of CAINE include: Autopsy, wireshark, regripper, photorec, fsstat, etc. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://www.caine-live.net/ |

## REMNUX (Not Used)
|Section |  Information|
|--|--|
|Description | Like previous tools, REMNUX is a custom Linux distribution with many digital forensic and incident response tools designed to make live easier for forensic investigators. REMNUX boasts features for malware analysis, network analysis, memory capture, etc. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | https://remnux.org/ |

## Faraday Bag (Not Used)
|Section |  Information|
|--|--|
|Description | A Faraday bag is a radio frequency shielded bag used in incidence response and digital forensics designed to ensure that no communications occur with a seized device such that it can maintain the same data integrity and state that it was it when first acquired. |
|Personal Review | N/A |
|Personal notes on Usage | N/A |
|Source | N/A |


