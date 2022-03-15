if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103856" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-12-16 11:11:45 +0100 (Mon, 16 Dec 2013)" );
	script_name( "Schneider Electric Modicon M340 Detection (http)" );
	script_tag( name: "summary", value: "Detection of Schneider Electric Modicon M340 over HTTP.

The script sends a HTTP request to the server and attempts to detect a Schneider Modicon M340 from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Schneider-WEB/banner" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Schneider-WEB" )){
	exit( 0 );
}
url = "/html/english/index.htm";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: TRUE );
if(!IsMatchRegexp( buf, "<title>.* (BMX P34) .*</title>" )){
	exit( 0 );
}
set_kb_item( name: "schneider_modicon_m340/installed", value: TRUE );
cpe = "cpe:/h:schneider-electric:modicon_m340";
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: "The remote Host is a Schneider Modicon M340.\nCPE: " + cpe + "\nLocation: /\n", port: port );
exit( 0 );

