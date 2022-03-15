if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106486" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-23 10:52:32 +0700 (Fri, 23 Dec 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Intercloud Fabric Detection" );
	script_tag( name: "summary", value: "Detection of Cisco Intercloud Fabric

The script sends a HTTP connection request to the server and attempts to detect the presence of Cisco Intercloud
Fabric and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
req = http_get( port: port, item: "/icfb/" );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "<title>Intercloud Fabric</title>" ) && ContainsString( res, "microloader" )){
	version = "unknown";
	vers = eregmatch( pattern: "ovaBuildNo = \"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "cisco/intercloud_fabric/version", value: version );
	}
	set_kb_item( name: "cisco/intercloud_fabric/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:intercloud_fabric:" );
	if(!cpe){
		cpe = "cpe:/a:cisco:intercloud_fabric";
	}
	register_product( cpe: cpe, location: "/icfb", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Cisco Intercloud Fabric", version: version, install: "/icfb", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

