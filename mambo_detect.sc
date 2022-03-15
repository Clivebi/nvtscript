if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100036" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "mambo Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running mambo a widely installed Open Source cms solution." );
	script_xref( name: "URL", value: "http://www.mamboserver.com" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "mambo Detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/mambo", "/cms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if( egrep( pattern: "^Set-Cookie: mosvisitor=1", string: buf ) || egrep( pattern: ".*meta name=\"description\" content=\"This site uses Mambo.*", string: buf ) || egrep( pattern: ".*meta name=\"Generator\" content=\"Mambo.*", string: buf ) || egrep( pattern: ".*http://mambo-foundation.org<[^>]+>Mambo.*", string: buf ) ){
		installed = TRUE;
	}
	else {
		url = NASLString( dir, "/htaccess.txt" );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(!buf){
			continue;
		}
		if( egrep( pattern: ".*# @package Mambo.*", string: buf ) ){
			installed = TRUE;
		}
		else {
			url = NASLString( dir, "/README.php" );
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(!buf){
				continue;
			}
			if( egrep( pattern: "^Mambo is Open Source software.*", string: buf ) ){
				installed = TRUE;
			}
			else {
				url = NASLString( dir, "/includes/js/mambojavascript.js" );
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(!buf){
					continue;
				}
				if(egrep( pattern: ".*@package Mambo.*", string: buf )){
					installed = TRUE;
				}
			}
		}
	}
	if(installed){
		vers = "unknown";
		url = dir + "/administrator/components/com_admin/version.xml";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		version = eregmatch( string: buf, pattern: "<version>(.*)</version>" );
		if( !isnull( version[1] ) ){
			vers = version[1];
			concUrl = url;
		}
		else {
			url = NASLString( dir, "/mambots/content/moscode.xml" );
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			version = eregmatch( string: buf, pattern: ".*<version>(.*)</version>.*" );
			if( !isnull( version[1] ) ){
				vers = version[1];
				concUrl = url;
			}
			else {
				url = NASLString( dir, "/help/mambo.whatsnew.html" );
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				version = eregmatch( string: buf, pattern: ".*<h1>.*New in Version (.*)</h1>.*" );
				if(!isnull( version[1] )){
					vers = version[1];
					concUrl = url;
				}
			}
		}
		set_kb_item( name: "mambo_cms/detected", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:mambo-foundation:mambo:" );
		if(!cpe){
			cpe = "cpe:/a:mambo-foundation:mambo";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Mambo CMS", version: vers, install: install, cpe: cpe, concluded: version[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

