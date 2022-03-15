if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141184" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-15 09:53:35 +0700 (Fri, 15 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Seagate NAS Device Detection" );
	script_tag( name: "summary", value: "Detection of Seagate NAS devices.

The script sends a connection request to the server and attempts to detect Seagate NAS devices and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.seagate.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "NAS_CUSTOM_INFO" ) && ContainsString( res, "NAS_CUSTOM_INFO[\"VENDOR_NAME\"]" )){
	version = "unknown";
	url = "/api/external/7.0/system.System.get_infos";
	req = http_post( port: port, item: url, data: "{}" );
	res = http_keepalive_send_recv( port: port, data: req );
	prod = eregmatch( pattern: "\"product\": \"([^\"]+)", string: res );
	if( !isnull( prod[1] ) ){
		product = prod[1];
		set_kb_item( name: "seagate_nas/model", value: product );
	}
	else {
		exit( 0 );
	}
	vers = eregmatch( pattern: "\"version\": \"([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = url;
	}
	set_kb_item( name: "seagate_nas/detected", value: TRUE );
	cpe_base = "cpe:/h:seagate:" + str_replace( string: tolower( product ), find: " ", replace: "_" );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: cpe_base + ":" );
	if(!cpe){
		cpe = cpe_base;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Seagate " + product, version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

