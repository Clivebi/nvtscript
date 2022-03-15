if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113040" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-25 13:04:05 +0200 (Wed, 25 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ArcGIS Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of ArcGIS Server.

    This script sends an HTTP GET request and tries to get the version from the
    response." );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/arcgis/rest/services/" );
if(ContainsString( res, "ArcGIS REST Services Directory" )){
	version = "unknown";
	vers = eregmatch( pattern: "<b>Current Version: </b>(([0-9]+\\.)+[0-9]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "arcgis/version", value: version );
	}
	set_kb_item( name: "arcgis/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:esri:arcgis:" );
	if(!cpe){
		cpe = "cpe:/a:esri:arcgis";
	}
	register_product( cpe: cpe, location: "/arcgis/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ArcGIS Server", version: version, install: "/arcgis/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

