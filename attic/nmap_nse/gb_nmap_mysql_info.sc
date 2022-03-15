if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801282" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2010-09-23 08:22:30 +0200 (Thu, 23 Sep 2010)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Nmap NSE: MySQL Info" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2010 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "This script attempts to connect to a MySQL server and extract
  information.

  This is a wrapper on the Nmap Security Scanner's mysql-info.nse" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

