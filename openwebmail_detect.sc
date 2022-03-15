if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14221" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Open WebMail Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.openwebmail.org" );
	script_tag( name: "summary", value: "This script detects whether the target is running Open WebMail and
  extracts version numbers and locations of any instances found.

  Open WebMail is a webmail package written in Perl that provides access
  to mail accounts via POP3 or IMAP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
installs = 0;
rel = NULL;
for dir in nasl_make_list_unique( "/", "/cgi-bin/openwebmail", "/openwebmail-cgi", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/openwebmail.pl";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(isnull( res )){
		continue;
	}
	if(egrep( string: res, pattern: "^HTTP/1\\.[01] 200" ) && egrep( string: res, pattern: "(http://openwebmail\\.org|Open WebMail)" )){
		version = "unknown";
		pat = "^version (.+)$";
		matches = egrep( pattern: pat, string: res );
		for match in split( matches ) {
			match = chomp( match );
			vers = eregmatch( pattern: pat, string: match );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
			break;
		}
		if(version == "unknown"){
			pat = "([^\'\"]*/openwebmail)/(images|help)/";
			matches = egrep( pattern: pat, string: res );
			for match in split( matches ) {
				match = chomp( match );
				data_url = eregmatch( string: match, pattern: pat );
				if(!isnull( data_url )){
					data_url = data_url[1];
				}
				break;
			}
			if(!isnull( data_url )){
				url = data_url + "/doc/changes.txt";
				req = http_get( item: url, port: port );
				res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(!isnull( res ) && egrep( string: res, pattern: "^HTTP/1\\.[01] 200" )){
					pat = "^[01][0-9]/[0-3][0-9]/20[0-9][0-9]( +.version .+)?";
					matches = egrep( pattern: pat, string: res );
					for match in split( matches ) {
						match = chomp( match );
						vers = eregmatch( pattern: "version +(.+).$", string: match );
						concUrl = url;
						if( isnull( vers[1] ) ){
							if(isnull( rel )){
								parts = split( buffer: match, sep: "/", keep: FALSE );
								rel = NASLString( parts[2], parts[0], parts[1] );
							}
						}
						else {
							version = vers[1];
							if(!isnull( rel )){
								version += " " + rel;
							}
							break;
						}
					}
				}
			}
		}
		set_kb_item( name: "OpenWebMail/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9. ]+)", base: "cpe:/a:openwebmail.acatysmoof:openwebmail:" );
		if(!cpe){
			cpe = "cpe:/a:openwebmail.acatysmoof:openwebmail";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Open WebMail", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

