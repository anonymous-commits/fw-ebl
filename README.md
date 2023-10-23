# fw-ebl

This repository contains scripts to update embedded OS firewalls with dynamically downloaded block list IP-addresses.<br/>
The scripts will take multiple "EBL" formated textfiles, that is a text file containing _ONE_ IP-address or CIDR per row. Everything on a line after a comment will be ignored.<br/>
The EBL files can be referenced from filesystem or a URL.<br/>
The scripts will create multiple outbound block/deny rules per source list, but will chunk as many IP's togheter in one rule that is apporpriate per implementation.<br/>
Key use case beeing that you have a list of "bad IPs", could be C2-servers or something else.<br/>

The script defender-ebl.ps1 is a powershell script intended to be run on a stand alone computer.<br/>
The script defender-ebl-gpo.ps1 is a powershell script intended for domain joined computers, it updates a GPO that can be linked to your target computers.<br/>

There might be other scripts and ansible playbooks etc in the futher.<br/>
There are plans to make scripts for Linux-systems (combo RHEL firewalld and Ubuntu ufw) as well as Windows.
