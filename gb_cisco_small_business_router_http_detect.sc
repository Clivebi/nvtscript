if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141918" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-25 09:35:38 +0700 (Fri, 25 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Small Business Router Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Cisco Small Business Routers.

The script sends a HTTP(S) connection request to the server and attempts to detect Cisco Small Business Routers." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.cisco.com/c/en/us/solutions/small-business/routers.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>Router</title>" ) && ContainsString( res, "trademarks of Cisco Systems" ) && ContainsString( res, "getElementById(\"nk_login\")" )){
	version = "unknown";
	set_kb_item( name: "cisco/smb_router/detected", value: TRUE );
	set_kb_item( name: "cisco/smb_router/http/port", value: port );
	log_message( data: build_detection_report( app: "Cisco Small Business Router", version: version, install: "/" ), port: port );
	exit( 0 );
}
exit( 0 );

