if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100330" );
	script_version( "2021-09-27T07:55:19+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-27 07:55:19 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)" );
	script_name( "Joomla Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Angelo Compagnucci" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Joomla." );
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
for dir in nasl_make_list_unique( "/", "/cms", "/joomla", http_cgi_dirs( port: port ) ) {
	installed = FALSE;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf || ContainsString( buf, "topic does not exist" ) || ContainsString( buf, "content=\"DokuWiki\"" )){
		continue;
	}
	if( egrep( pattern: ".*content=\"joomla.*", string: buf ) || egrep( pattern: ".*content=\"Joomla.*", string: buf ) || egrep( pattern: ".*href=\"/administrator/templates.*", string: buf ) || egrep( pattern: ".*src=\"/media/system/js.*", string: buf ) || egrep( pattern: ".*src=\"/templates/system.*", string: buf ) ){
		installed = TRUE;
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	else {
		url = dir + "/.htaccess";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if( egrep( pattern: ".*# @package Joomla.*", string: buf ) ){
			installed = TRUE;
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		else {
			url = dir + "/templates/system/css/editor.css";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if( egrep( pattern: ".*JOOMLA.*", string: buf ) ){
				installed = TRUE;
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			else {
				url = dir + "/includes/js/mambojavascript.js";
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(egrep( pattern: ".*@package Joomla.*", string: buf )){
					installed = TRUE;
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
	}
	if(installed){
		version = "unknown";
		url = dir + "/administrator/";
		buf = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			language = eregmatch( string: buf, pattern: "lang=\"(..-..)\"" );
		}
		default_lang = make_list( "en-GB" );
		if( !isnull( language[1] ) ){
			lang = substr( language[1], 0, 1 ) + "-" + toupper( substr( language[1], 3 ) );
			langs = make_list( default_lang,
				 lang );
		}
		else {
			langs = default_lang;
		}
		check_files = make_list( "install.xml",
			 lang + ".xml" );
		for check_file in check_files {
			for lang in langs {
				url = dir + "/administrator/language/" + lang + "/" + check_file;
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
					ver = eregmatch( string: buf, pattern: "<version>([^<]+)</version>" );
				}
				if(!isnull( ver[1] )){
					if(conclUrl){
						conclUrl += " and " + http_report_vuln_url( url: url, port: port, url_only: TRUE );
					}
					version = ver[1];
					concluded = ver[0];
					break;
				}
			}
			if(version != "unknown"){
				break;
			}
		}
		if(version == "unknown"){
			url = dir + "/";
			buf = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
				language = eregmatch( string: buf, pattern: "lang=\"(..-..)\"" );
			}
			if( !isnull( language[1] ) ){
				lang = substr( language[1], 0, 1 ) + "-" + toupper( substr( language[1], 3 ) );
				langs = make_list( default_lang,
					 lang );
			}
			else {
				langs = default_lang;
			}
			check_files = make_list( "install.xml",
				 lang + ".xml" );
			for check_file in check_files {
				for lang in langs {
					url = dir + "/language/" + lang + "/" + check_file;
					req = http_get( item: url, port: port );
					buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
					if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
						ver = eregmatch( string: buf, pattern: "<version>([^<]+)</version>" );
					}
					if(!isnull( ver[1] )){
						if(conclUrl){
							conclUrl += " and " + http_report_vuln_url( url: url, port: port, url_only: TRUE );
						}
						version = ver[1];
						concluded = ver[0];
						break;
					}
				}
				if(version != "unknown"){
					break;
				}
			}
		}
		if(version == "unknown"){
			url = dir + "/components/com_user/user.xml";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
				ver = eregmatch( string: buf, pattern: "<version>([^<]+)</version>" );
			}
			if(!isnull( ver[1] )){
				if(conclUrl){
					conclUrl += " and " + http_report_vuln_url( url: url, port: port, url_only: TRUE );
				}
				version = ver[1];
				concluded = ver[0];
			}
		}
		if(version == "unknown"){
			url = dir + "/modules/mod_login/mod_login.xml";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
				ver = eregmatch( string: buf, pattern: "<version>([^<]+)</version>" );
			}
			if(!isnull( ver[1] )){
				if(conclUrl){
					conclUrl += " and " + http_report_vuln_url( url: url, port: port, url_only: TRUE );
				}
				version = ver[1];
				concluded = ver[0];
			}
		}
		set_kb_item( name: "joomla/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:joomla:joomla:" );
		if(!cpe){
			cpe = "cpe:/a:joomla:joomla";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Joomla", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: concluded ), port: port );
		exit( 0 );
	}
}
exit( 0 );

