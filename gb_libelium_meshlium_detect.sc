if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141430" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-05 16:20:51 +0700 (Wed, 05 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Libelium Meshlium IoT Gateway Detection" );
	script_tag( name: "summary", value: "Detection of Libelium Meshlium IoT Gateway.

The script sends a connection request to the server and attempts to detect Libelium Meshlium IoT Gateway and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.libelium.com/products/meshlium/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/ManagerSystem/login.php" );
if(ContainsString( res, "<title>Meshlium Manager System</title>" ) && ContainsString( res, "Libelium Comunicaciones" )){
	version = "unknown";
	url = "/MeshliumInfo/";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "ManagerSystem Version</td>[^>]+>([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	mac = eregmatch( pattern: "MAC</td>[^>]+>([0-9a-f:]{17})", string: res );
	if(!isnull( mac[1] )){
		register_host_detail( name: "MAC", value: mac[1], desc: "gb_libelium_meshlium_detect.nasl" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
		extra += "\nMAC Address:   " + mac[1];
	}
	set_kb_item( name: "libelium_meshlium/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:libelium:meshlium:" );
	if(!cpe){
		cpe = "cpe:/a:libelium:meshlium";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Libelium Meshlium", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

