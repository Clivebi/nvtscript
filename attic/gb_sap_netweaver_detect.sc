if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105302" );
	script_version( "2021-04-26T09:41:42+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-26 09:41:42 +0000 (Mon, 26 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-06-22 11:54:01 +0200 (Mon, 22 Jun 2015)" );
	script_name( "SAP NetWeaver Application Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to extract the version number from the reply.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

