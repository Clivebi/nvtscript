if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145487" );
	script_version( "2021-09-09T10:20:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:20:36 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-03-03 07:09:16 +0000 (Wed, 03 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HP / HPE Systems Insight Manager (SIM) Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of HP / HPE Systems Insight Manager (SIM)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 50000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.hp.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 50000 );
res = http_get_cache( port: port, item: "/" );
if(( IsMatchRegexp( res, "<title>HPE? Systems? Insight Manager" ) && IsMatchRegexp( res, "signInTitle\"><h[0-9]>HPE? Systems? Insight Manager" ) ) || IsMatchRegexp( res, "<li>Obtain an exported HPE? Systems? Insight Manager server certificate file from the administrator\\.</li>" ) || IsMatchRegexp( res, "<h[0-9]>Please insert your Smart Card and login to HPE? Systems? Insight Manager\\.</h[0-9]></td>" )){
	version = "unknown";
	set_kb_item( name: "hp_hpe/systems_insight_manager/detected", value: TRUE );
	set_kb_item( name: "hp_hpe/systems_insight_manager/http/detected", value: TRUE );
	cpe = "cpe:/a:hp:systems_insight_manager";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "HP / HPE Systems Insight Manager (SIM)", version: version, install: "/", cpe: cpe ), port: port );
	exit( 0 );
}
exit( 0 );

