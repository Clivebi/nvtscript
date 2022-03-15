if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803566" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:55 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: smtp-strangeport" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Checks if SMTP is running on a non-standard port.

This may indicate that an attacker has set up a backdoor on the system to send spam
or control the machine." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

