if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103677" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "creation_date", value: "2013-03-14 13:25:22 +0100 (Thu, 14 Mar 2013)" );
	script_name( "Cisco Video Surveillance Management Console Detection" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Cisco Video Surveillance Management Console.

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/vsmc.html";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<title>Video Surveillance Management Console</title>" )){
	url = "/inc/packages.php";
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "<title>Configuration Overview" )){
		version = eregmatch( pattern: "Cisco_VSMS-([^ \n\r]+)", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
		}
	}
}
if(!vers){
	url = "/vsom/";
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "<title>Video Surveillance Operations Manager" ) && ContainsString( buf, "Login</title>" )){
		vers = "unknown";
		version = eregmatch( pattern: "version\">Version ([^<]+)<", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
		}
	}
}
if(!vers){
	exit( 0 );
}
set_kb_item( name: NASLString( "www/", port, "/cisco_video_surveillance_manager" ), value: NASLString( vers, " under /" ) );
set_kb_item( name: "cisco_video_surveillance_manager/installed", value: TRUE );
cpe = build_cpe( value: vers, exp: "^(.*)$", base: "cpe:/a:cisco:video_surveillance_manager:" );
if(isnull( cpe )){
	cpe = "cpe:/a:cisco:video_surveillance_manager";
}
register_product( cpe: cpe, location: url, port: port, service: "www" );
log_message( data: build_detection_report( app: "Cisco Video Surveillance Manager", version: vers, install: url, cpe: cpe, concluded: version[0] ), port: port );
exit( 0 );

