if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106387" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-11-14 16:34:55 +0700 (Mon, 14 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Trango Systems Devices Detection" );
	script_tag( name: "summary", value: "Detection of Trango Systems Devices

  The script sends a connection request to the server and attempts to detect the presence of Trango Systems
Devices and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.trangosys.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "WWW-Authenticate: Basic realm=" ) && IsMatchRegexp( res, "(TrangoLINK|(Apex Lynx)|(Giga Lynx)|(Giga Orion)|(StrataLink))" )){
	version = "unknown";
	mod = eregmatch( pattern: "TrangoLINK(-| )([a-zA-Z]+)", string: res );
	if( !isnull( mod[2] ) ) {
		model = mod[2];
	}
	else {
		if( IsMatchRegexp( res, "Apex Lynx" ) ) {
			model = "Apex Lynx";
		}
		else {
			if( IsMatchRegexp( res, "Giga Lynx" ) ) {
				model = "Giga Lynx";
			}
			else {
				if( IsMatchRegexp( res, "Giga Orion" ) ) {
					model = "Giga Orion";
				}
				else {
					if( IsMatchRegexp( res, "StrataLink" ) ) {
						model = "StrataLink";
					}
					else {
						exit( 0 );
					}
				}
			}
		}
	}
	vers = eregmatch( pattern: model + "( [0-9]+)? v([0-9.]+)", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
		set_kb_item( name: "trangosystems/version", value: version );
	}
	set_kb_item( name: "trangosystems/detected", value: TRUE );
	set_kb_item( name: "trangosystems/model", value: model );
	cpemod = tolower( str_replace( string: model, find: " ", replace: "" ) );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:trango:" + cpemod + ":" );
	if(!cpe){
		cpe = "cpe:/a:trango:" + cpemod;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Trango Systems " + model, version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

