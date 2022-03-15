if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141250" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-29 13:36:40 +0200 (Fri, 29 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ASUSTOR Data Master (ADM) Detection" );
	script_tag( name: "summary", value: "Detection of ASUSTOR Data Master (ADM).

The script sends a connection request to the server and attempts to detect ASUSTOR Data Master (ADM) and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.asustor.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
res = http_get_cache( port: port, item: "/portal/" );
if(ContainsString( res, "login-nas-model" ) && ContainsString( res, "nasModel =" ) && ContainsString( res, "fwType = " )){
	version = "unknown";
	mod = eregmatch( pattern: "nasModel ='([^']+)", string: res );
	if(!isnull( mod[1] )){
		model = mod[1];
		set_kb_item( name: "asustor_adm/model", value: model );
	}
	vers = eregmatch( pattern: "var _dcTag = '([^']+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "asustor_adm/detected", value: TRUE );
	cpe = build_cpe( value: tolower( version ), exp: "^([0-9a-z.]+)", base: "cpe:/h:asustor:adm_firmware:" );
	if(!cpe){
		cpe = "cpe:/h:asustor:adm_firmware";
	}
	register_product( cpe: cpe, location: "/portal", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ASUSTOR Data Master " + model, version: version, install: "/portal", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

