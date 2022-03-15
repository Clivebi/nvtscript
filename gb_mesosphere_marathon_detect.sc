if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114011" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-20 11:00:14 +0200 (Fri, 20 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Mesoshpere Marathon UI Detection" );
	script_tag( name: "summary", value: "Detection of Mesosphere Marathon Web UI.

  The script sends a connection request to the server and attempts to detect Mesoshpere Marathon UI and to
  extract its version if possible." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://mesosphere.github.io/marathon/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/ui/main.js";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "marathon-ui - The web UI for Mesosphere's Marathon." ) || ContainsString( res, "function(e,t){e.exports={name:\"marathon-ui\"" )){
	version = "unknown";
	install = "/";
	vers = eregmatch( pattern: "version v([0-9.]+)", string: res );
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "mesosphere/marathon/detected", value: TRUE );
	set_kb_item( name: "mesosphere/marathon/version", value: version );
	set_kb_item( name: "mesosphere/marathon/" + port + "/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:mesosphere:marathon:" );
	if(!cpe){
		cpe = "cpe:/a:mesosphere:marathon";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Mesosphere Marathon", version: version, install: install, cpe: cpe, concludedUrl: conclUrl ), port: port );
}
exit( 0 );

