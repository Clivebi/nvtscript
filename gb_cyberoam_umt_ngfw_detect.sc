if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106864" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-06-12 15:55:23 +0700 (Mon, 12 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Sophos Cyberoam UMT/NGFW Detection" );
	script_tag( name: "summary", value: "Detection of Sophos Cyberoam UMT/NGFW.

The script sends a connection request to the server and attempts to detect Sophos Cyberoam UMT/NGFW
devices and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.cyberoam.com/networksecurity.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/corporate/webpages/login.jsp" );
if(ContainsString( res, "<title>Cyberoam</title>" ) && ContainsString( res, "OWN_STATUS" ) && ContainsString( res, "AUXILIARY" )){
	version = "unknown";
	vers = eregmatch( pattern: "ver=([0-9.]+) build ([0-9])([0-9]+)", string: res );
	if(!isnull( vers[1] ) && !isnull( vers[2] ) && !isnull( vers[3] )){
		version = vers[1] + "." + vers[2] + "." + vers[3];
		set_kb_item( name: "cyberoam_umt_ngfw/version", value: version );
	}
	set_kb_item( name: "cyberoam_umt_ngfw/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/o:cyberoam:cyberoam_os:" );
	if(!cpe){
		cpe = "cpe:/o:cyberoam:cyberoam_os";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	os_register_and_report( os: "Cyberoam OS", cpe: cpe, port: port, banner_type: "HTTP login page", desc: "Cyberoam Detection", runs_key: "unixoide" );
	log_message( data: build_detection_report( app: "Sophos Cyberoam UMT/NGFW", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

