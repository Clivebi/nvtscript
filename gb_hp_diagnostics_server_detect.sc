if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802389" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-02 10:43:19 +0530 (Thu, 02 Feb 2012)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "HP Diagnostics Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2006 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of HP Diagnostics Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 2006 );
res = http_get_cache( item: "/", port: port );
if(( ContainsString( res, ">HP Diagnostics" ) && ContainsString( res, "Hewlett-Packard Development" ) ) || ( ContainsString( res, ">HPE Diagnostics" ) && ContainsString( res, "diagName\">Diagnostics Server" ) )){
	version = "unknown";
	vers = eregmatch( pattern: ">Server ([0-9.]+)", string: res );
	if(!vers){
		vers = eregmatch( pattern: "version\">Version ([0-9.]+)", string: res );
	}
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "hp/diagnostics_server/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:diagnostics_server:" );
	if(!cpe){
		cpe = "cpe:/a:hp:diagnostics_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "HP Diagnostics Server", version: vers, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
}
exit( 0 );

