if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900608" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "WS_FTP Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/ws_ftp/detected" );
	script_tag( name: "summary", value: "This script determines the WS_FTP server version on the remote host
  and sets the result in the KB." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "WS_FTP Server" )){
	exit( 0 );
}
install = port + "/tcp";
version = "unknown";
set_kb_item( name: "ipswitch/ws_ftp_server/detected", value: TRUE );
vers = eregmatch( pattern: "WS_FTP Server ([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ipswitch:ws_ftp_server:" );
if(!cpe){
	cpe = "cpe:/a:ipswitch:ws_ftp_server";
}
register_product( cpe: cpe, location: install, port: port, service: "ftp" );
log_message( data: build_detection_report( app: "WS_FTP Server", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
exit( 0 );

