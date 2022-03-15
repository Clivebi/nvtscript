if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113069" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-14 13:04:05 +0100 (Thu, 14 Dec 2017)" );
	script_name( "MikroTik RouterOS Detection (FTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/mikrotik/detected" );
	script_tag( name: "summary", value: "Detection of MikroTik RouterOS via FTP.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !IsMatchRegexp( banner, " FTP server \\(MikroTik .* ready" )){
	exit( 0 );
}
version = "unknown";
install = port + "/tcp";
set_kb_item( name: "mikrotik/detected", value: TRUE );
set_kb_item( name: "mikrotik/ftp/detected", value: TRUE );
vers = eregmatch( pattern: "FTP server \\(MikroTik ([A-Za-z0-9.]+)", string: banner );
if(vers[1]){
	version = vers[1];
	set_kb_item( name: "mikrotik/ftp/" + port + "/concluded", value: vers[0] );
}
set_kb_item( name: "mikrotik/ftp/port", value: port );
set_kb_item( name: "mikrotik/ftp/" + port + "/version", value: version );
exit( 0 );

