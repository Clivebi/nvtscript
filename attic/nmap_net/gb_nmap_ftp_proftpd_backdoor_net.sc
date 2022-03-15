if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104030" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Nmap NSE net: ftp-proftpd-backdoor" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Tests for the presence of the ProFTPD 1.3.3c backdoor reported as OSVDB-ID 69562. This script
attempts to exploit the backdoor using the innocuous 'id' command by default, but that
can be changed with the 'ftp-proftpd-backdoor.cmd' script argument.

SYNTAX:

ftp-proftpd-backdoor.cmd:  Command to execute in shell (default is
'id')." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

