if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141651" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-06 16:12:43 +0700 (Tue, 06 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Citrix SD-WAN Detection" );
	script_tag( name: "summary", value: "Detection of Citrix SD-WAN.

The script sends a connection request to the server and attempts to detect Citrix SD-WAN and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.citrix.com/products/citrix-sd-wan/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/cgi-bin/login.cgi" );
if(ContainsString( res, "/vw/css/vw.css" ) && ContainsString( res, "citrix_login_logo" ) && IsMatchRegexp( res, "<title>[^|]+| Login</title>" )){
	version = "unknown";
	vers = eregmatch( pattern: "vw.css\\?R([0-9_]+)", string: res );
	if(!isnull( vers[1] )){
		version = str_replace( string: vers[1], find: "_", replace: "." );
	}
	set_kb_item( name: "citrix_sdwan/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:citrix:sd-wan:" );
	if(!cpe){
		cpe = "cpe:/a:citrix:sd-wan";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Citrix SD-WAN", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

