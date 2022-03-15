if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803520" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:09 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: ftp-bounce" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Checks to see if an FTP server allows port scanning using the FTP bounce method.

SYNTAX:

ftp-bounce.username:  Username to log in with. Default
''anonymous''.

ftp-bounce.password:  Password to log in with. Default
''IEUser@''." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

