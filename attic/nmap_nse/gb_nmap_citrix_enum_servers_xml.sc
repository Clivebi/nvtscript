if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801822" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-01-21 13:17:02 +0100 (Fri, 21 Jan 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE: Citrix Enum Servers XML" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "This script attempts to extract the name of the server farm and
  member servers from Citrix XML service.

  This is a wrapper on the Nmap Security Scanner's citrix-enum-servers-xml.nse." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

