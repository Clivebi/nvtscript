if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19559" );
	script_version( "2021-03-05T11:52:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-05 11:52:26 +0000 (Fri, 05 Mar 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "CiscoWorks Management Console Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 TNS" );
	script_family( "Product detection" );
	script_tag( name: "summary", value: "This VT has been replaced by VT CiscoWorks Detection (HTTP) (OID: 1.3.6.1.4.1.25623.1.0.145409).

  The remote host appears to be running CiscoWorks, a LAN Management Solution,
  on this port." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

