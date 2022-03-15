if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811880" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-25 14:30:38 +0530 (Wed, 25 Oct 2017)" );
	script_name( "TP-Link Wireless Router Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of TP-Link Wireless Routers." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(banner && IsMatchRegexp( banner, "WWW-Authenticate: Basic realm=\"TP-Link.*Wireless.*Router" )){
	set_kb_item( name: "TP-LINK/Wireless/Router/detected", value: TRUE );
	app = "TP-Link Wireless Router";
	cpe = "cpe:/h:tp-link:wireless-n_router";
	location = "/";
	version = "unknown";
	model = eregmatch( pattern: "TP-LINK.*Wireless.*Router ([A-Z0-9\\-\\/\\s]+)", string: banner, icase: TRUE );
	if(model[1]){
		set_kb_item( name: "TP-LINK/Wireless/Router/model", value: model[1] );
		app = model[0];
		concl = model[0];
	}
	register_product( cpe: cpe, location: location, port: port, service: "www" );
	log_message( data: build_detection_report( app: app, version: version, install: location, cpe: cpe, concluded: concl ), port: port );
	exit( 0 );
}
exit( 0 );

