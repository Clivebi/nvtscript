if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19602" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Land Down Under (LDU) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2006 Josh Zlatin-Amishav" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.neocrome.net/" );
	script_tag( name: "summary", value: "HTTP based detection of Land Down Under (LDU)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "^Set-Cookie: LDUC" ) || ContainsString( res, "content=\"Land Down Under Copyright Neocrome" ) || ContainsString( res, "content=\"LDU,land,down,under" )){
		version = "unknown";
		pat = "Powered by <a [^<]+ LDU ([0-9.]+)<";
		matches = egrep( pattern: pat, string: res );
		if(matches){
			for match in split( matches ) {
				match = chomp( match );
				ver = eregmatch( pattern: pat, string: match );
				if(!isnull( ver )){
					version = ver[1];
					break;
				}
			}
		}
		if(version == "unknown"){
			req = http_get( item: dir + "/docs/readme.old_documentation.htm", port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			pat = "id=\"top\"></a>Land Down Under v([0-9]+)<";
			matches = egrep( pattern: pat, string: res );
			if(matches){
				for match in split( matches ) {
					match = chomp( match );
					ver = eregmatch( pattern: pat, string: match );
					if(!isnull( ver )){
						version = ver[1];
						break;
					}
				}
			}
		}
		set_kb_item( name: "ldu/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:neocrome:land_down_under:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:neocrome:land_down_under";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Land Down Under (LDU)", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

