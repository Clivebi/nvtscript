if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106797" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-28 11:40:45 +0200 (Fri, 28 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Logrhythm Network Monitor Detection" );
	script_tag( name: "summary", value: "Detection of Logrhythm Network Monitor.

The script sends a connection request to the server and attempts to detect Logrhythm Network Monitor and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://logrhythm.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/login" );
if(ContainsString( res, "<title>Logrhythm Network Monitor</title>" ) && ContainsString( res, "analyze/dist/app.bundle.js" )){
	version = "unknown";
	req = http_get( port: port, item: "/userDocs/Content/1_Introduction/1c_AboutGuide.htm" );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "MyVariablesVersion\">([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "logrhythm_netmon/version", value: version );
	}
	set_kb_item( name: "logrhythm_netmon/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:logrhythm:network_monitor:" );
	if(!cpe){
		cpe = "cpe:/a:logrhythm:network_monitor";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Logrhythm Network Monitor", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

