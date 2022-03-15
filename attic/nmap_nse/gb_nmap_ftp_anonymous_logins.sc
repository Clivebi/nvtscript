if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801260" );
	script_version( "2020-07-07T08:05:40+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 08:05:40 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2010-08-30 16:16:51 +0200 (Mon, 30 Aug 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Nmap NSE: FTP Anon" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2010 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "This script attempts to check if an FTP server allows anonymous logins.

  This is a wrapper on the Nmap Security Scanner's ftp-anon.nse" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

