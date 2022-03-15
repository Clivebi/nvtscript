if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106951" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-07-14 09:53:13 +0700 (Fri, 14 Jul 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dasan Networks GPON ONT Devices Detection" );
	script_tag( name: "summary", value: "Detection of Dasan Networks GPON ONT devices.

The script sends a connection request to the server and attempts to detect Dasan Networks GPON ONT devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.dasannetworks.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/cgi-bin/login.cgi" );
if(ContainsString( res, "<title>GPON ONT</title>" ) && ContainsString( res, "dasan_logo.png" ) && ContainsString( res, "\"WebTitle\", \"GPON ONT\"" )){
	version = "unknown";
	set_kb_item( name: "dasan_gpon_ont/detected", value: TRUE );
	cpe = "cpe:/a:dansan_networks:gpon_ont";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dasan Networks GPON ONT", version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

