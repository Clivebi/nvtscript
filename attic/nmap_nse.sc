if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810010" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2010-08-10 12:08:05 +0200 (Tue, 10 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Launch Nmap NSE Tests" );
	script_category( ACT_SETTINGS );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "This script controls the execution of Nmap NSE Tests" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

