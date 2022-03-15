if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801117" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SolarWinds Serv-U Detection (FTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_mandatory_keys( "ftp/serv-u/detected" );
	script_tag( name: "summary", value: "Detection of SolarWinds Serv-U.

  This script performs FTP based detection of SolarWinds Serv-U." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "Serv-U" )){
	exit( 0 );
}
vers = eregmatch( string: banner, pattern: "Name=Serv-U; Version=([^;]+);" );
if( !isnull( vers[1] ) ){
	set_kb_item( name: "solarwinds/servu/ftp/" + port + "/version", value: vers[1] );
	set_kb_item( name: "solarwinds/servu/ftp/" + port + "/concluded", value: banner );
}
else {
	vers = eregmatch( pattern: "Serv-U FTP Server v([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		set_kb_item( name: "solarwinds/servu/ftp/" + port + "/version", value: vers[1] );
		set_kb_item( name: "solarwinds/servu/ftp/" + port + "/concluded", value: banner );
	}
}
set_kb_item( name: "solarwinds/servu/detected", value: TRUE );
set_kb_item( name: "solarwinds/servu/ftp/port", value: port );
exit( 0 );

