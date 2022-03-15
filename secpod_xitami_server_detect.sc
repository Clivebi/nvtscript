if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900547" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Xitami Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "ftpserver_detect_type_nd_version.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, "Services/ftp", 21, 990 );
	script_tag( name: "summary", value: "Detection of Xitami Server.

  This script tries to detect an installed Xitami Server and its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
ports = ftp_get_ports();
for port in ports {
	banner = ftp_get_banner( port: port );
	if(!banner || ( !ContainsString( banner, "Welcome to this Xitami FTP server" ) && !ContainsString( banner, "220 Xitami FTP " ) )){
		continue;
	}
	set_kb_item( name: "xitami/detected", value: TRUE );
	set_kb_item( name: "xitami/ftp/detected", value: TRUE );
	version = "unknown";
	install = port + "/tcp";
	vers = eregmatch( pattern: "(220 Xitami FTP |Xitami FTP server, running version )([0-9a-z.]+)", string: banner );
	if(vers[2]){
		version = vers[2];
		set_kb_item( name: "xitami/version", value: version );
		set_kb_item( name: "xitami/ftp/version", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:imatix:xitami:" );
	}
	if(!cpe){
		cpe = "cpe:/a:imatix:xitami";
	}
	register_product( cpe: cpe, location: install, port: port, service: "ftp" );
	log_message( data: build_detection_report( app: "Xitami Server", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
}
if(http_is_cgi_scan_disabled()){
	exit( 0 );
}
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
res = http_get_cache( port: port, item: "/" );
if(!res || ( !ContainsString( banner, "erver: Xitami" ) && !ContainsString( res, ">Welcome To Xitami " ) )){
	exit( 0 );
}
set_kb_item( name: "xitami/detected", value: TRUE );
set_kb_item( name: "xitami/http/detected", value: TRUE );
version = "unknown";
cpe = "";
install = port + "/tcp";
vers = eregmatch( pattern: "Welcome To Xitami v([0-9]\\.[0-9a-z.]+)", string: res );
if(vers[1]){
	version = vers[1];
	conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
}
if(version == "unknown"){
	vers = eregmatch( pattern: "Xitami(\\/([0-9]\\.[0-9.]+)([a-z][0-9]?)?)", string: banner );
	if(vers[1]){
		version = vers[1];
		conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	}
}
if(version == "unknown"){
	url = "/xitami/index.htm";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "Xitami</B>.*Version ([0-9]\\.[0-9a-z.]+)", string: res );
	if(vers[1]){
		version = vers[1];
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
}
if(version != "unknown"){
	set_kb_item( name: "xitami/version", value: version );
	set_kb_item( name: "xitami/http/version", value: version );
	cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:imatix:xitami:" );
}
if(!cpe){
	cpe = "cpe:/a:imatix:xitami";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Xitami Server", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
exit( 0 );

