if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103740" );
	script_version( "2021-07-28T09:20:09+0000" );
	script_tag( name: "last_modification", value: "2021-07-28 09:20:09 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-06-17 16:27:41 +0200 (Mon, 17 Jun 2013)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Plesk Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Plesk." );
	script_xref( name: "URL", value: "https://www.plesk.com/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8443 );
url = "/login_up.php3";
res = http_get_cache( item: url, port: port );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( IsMatchRegexp( res, "<title>(Parallels Plesk|Plesk( (Onyx|Obsidian))?)" ) || ContainsString( res, "name=\"plesk-build\"" ) )){
	version = "unknown";
	install = "/";
	vers = eregmatch( pattern: "<title>(Parallels Plesk( Panel)?|Plesk( (Onyx|Obsidian))?) ([0-9.]+)", string: res );
	if( !isnull( vers[5] ) ){
		version = vers[5];
	}
	else {
		vers = eregmatch( pattern: "\"urlArgs\":\"([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	set_kb_item( name: "plesk/detected", value: TRUE );
	set_kb_item( name: "plesk/http/detected", value: TRUE );
	base_cpe = "cpe:/a:parallels:parallels_plesk_panel";
	if(!isnull( vers[4] ) || IsMatchRegexp( version, "^1[78]\\." )){
		if( IsMatchRegexp( version, "^17\\." ) || vers[4] == "Onyx" ) {
			base_cpe = "cpe:/a:plesk:onyx";
		}
		else {
			base_cpe = "cpe:/a:plesk:obsidian";
		}
		rel = vers[4];
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: base_cpe + ":" );
	if(!cpe){
		cpe = base_cpe;
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Plesk " + rel, version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

