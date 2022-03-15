if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106627" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-03 10:33:24 +0700 (Fri, 03 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cambium Networks ePMP 1000 Detection" );
	script_tag( name: "summary", value: "Detection of Cambium Networks ePMP 1000

The script sends a HTTP connection request to the server and attempts to detect the presence of Cambium Networks
ePMP 1000 and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.cambiumnetworks.com/products/access/epmp-1000/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( res, "<title>ePMP( 1000)?</title>" ) && ContainsString( res, "data-inactive=\"No Internet Connectivity\"" ) && ContainsString( res, "cambium.min.css" )){
	version = "unknown";
	vers = eregmatch( pattern: "sw_version\">([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "epmp1000/version", value: version );
	}
	set_kb_item( name: "epmp1000/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:cambium_networks:epmp1000:" );
	if(!cpe){
		cpe = "cpe:/a:cambium_networks:epmp1000";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Cambium Networks ePMP 1000", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

