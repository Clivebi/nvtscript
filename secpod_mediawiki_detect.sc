if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900420" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)" );
	script_name( "MediaWiki Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of MediaWiki." );
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
max_tries = 5;
for dir in nasl_make_list_unique( "/wiki", "/mediawiki", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php/Special:Version";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	tries = 0;
	for(;IsMatchRegexp( res, "^HTTP/1\\.[01] 30[12]" );){
		tries += 1;
		if(path = http_extract_location_from_redirect( port: port, data: res, current_dir: install )){
			req = http_get( item: path, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		}
		if(tries >= max_tries){
			break;
		}
	}
	if(( IsMatchRegexp( res, "[Pp]owered by" ) || IsMatchRegexp( res, "name=\"generator\" content=\"MediaWiki" ) ) && ContainsString( res, "MediaWiki" ) && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		version = "unknown";
		ver = eregmatch( pattern: "MediaWiki ([0-9.]+)(.?([a-zA-Z0-9]+))?", string: res );
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		if(ver[1] != NULL){
			if( ver[3] != NULL ){
				version = ver[1] + "." + ver[2];
			}
			else {
				version = ver[1];
			}
		}
		set_kb_item( name: "mediawiki/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:mediawiki:mediawiki:" );
		if(!cpe){
			cpe = "cpe:/a:mediawiki:mediawiki";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "MediaWiki", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

