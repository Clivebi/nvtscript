if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106075" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-05-17 08:27:15 +0700 (Tue, 17 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Sierra Wireless AceManager Detection" );
	script_tag( name: "summary", value: "Detection of Sierra Wireless AceManager

The script sends a connection request to the server and attempts to detect Sierra Wireless AceManager which
is a web based utility to manage and configure AirLink devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.sierrawireless.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9443 );
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, "Server: Sierra Wireless Inc, Embedded Server" ) && ContainsString( res, "<title>::: ACEmanager :::</title>" ) && ContainsString( res, "Sierra Wireless, Inc." )){
	vers = NASLString( "unknown" );
	set_kb_item( name: NASLString( "www/", port, "/acemanager" ), value: vers );
	set_kb_item( name: "sierra_wireless_acemanager/installed", value: TRUE );
	cpe = "cpe:/h:sierra_wireless:acemanager";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Sierra Wireless AceManager", version: vers, install: "/", cpe: cpe ), port: port );
}
exit( 0 );

