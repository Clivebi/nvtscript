if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141022" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-25 12:19:41 +0700 (Wed, 25 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "iPECS NMS Detection" );
	script_tag( name: "summary", value: "Detection of iPECS NMS.

The script sends a connection request to the server and attempts to detect iPECS NMS." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.ipecs.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>iPECS NMS</title>" ) && ContainsString( res, "images/ipecs.png" )){
	version = "unknown";
	set_kb_item( name: "ipecs_nms/installed", value: TRUE );
	cpe = "cpe:/a:ipecs:nms";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "iPECS NMS", version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

