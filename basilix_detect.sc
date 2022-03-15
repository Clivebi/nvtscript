if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14308" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "BasiliX Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/basilix/" );
	script_tag( name: "summary", value: "The remote web server contains a webmail application written in PHP.

  Description :

  This script detects whether the remote host is running BasiliX and extracts version numbers and locations of any
  instances found.

  BasiliX is a webmail application based on PHP and IMAP and powered by MySQL." );
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
installs = 0;
for dir in nasl_make_list_unique( "/basilix", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/basilix.php" );
	if(port == 443){
		url = NASLString( url, "?is_ssl=1" );
	}
	req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", "Cookie: BSX_TestCookie=yes\\r\\n", "\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(res == NULL){
		exit( 0 );
	}
	if(ContainsString( res, "BasiliX" )){
		title = strstr( res, "<title>" );
		if(title != NULL){
			title = title - strstr( title, NASLString( "\\n" ) );
			pat = "BasiliX (.+)</title>";
			ver = eregmatch( pattern: pat, string: title, icase: TRUE );
			if(ver != NULL){
				ver = ver[1];
			}
		}
		if(isnull( ver )){
			generator = strstr( res, "<meta name=\"generator\"" );
			if(generator != NULL){
				generator = generator - strstr( generator, NASLString( "\\n" ) );
				pat = "content=\"BasiliX (.+)\"";
				ver = eregmatch( pattern: pat, string: generator, icase: TRUE );
				if(ver != NULL){
					ver = ver[1];
				}
			}
		}
		if(isnull( ver )){
			copyright = strstr( res, "BasiliX v" );
			if(copyright != NULL){
				copyright = copyright - strstr( copyright, NASLString( "\\n" ) );
				pat = "BasiliX v(.+) -- &copy";
				ver = eregmatch( pattern: pat, string: copyright, icase: TRUE );
				if(ver != NULL){
					ver = ver[1];
				}
			}
		}
		set_kb_item( name: "basilix/installed", value: TRUE );
		if(!isnull( ver )){
			tmp_version = NASLString( ver, " under ", dir );
			set_kb_item( name: NASLString( "www/", port, "/basilix" ), value: tmp_version );
			cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", base: "cpe:/a:basilix:basilix_webmail:" );
			if(!cpe){
				cpe = "cpe:/a:basilix:basilix_webmail";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			installations[dir] = ver;
			++installs;
		}
		if(installs){
			break;
		}
	}
}
if(installs){
	if( installs == 1 ){
		for dir in keys( installations ) {
			}
		info = NASLString( "BasiliX ", ver, " was detected on the remote host under the path ", dir, "." );
	}
	else {
		info = NASLString( "Multiple instances of BasiliX were detected on the remote host:\\n", "\\n" );
		for dir in keys( installations ) {
			info = info + NASLString( "    ", installations[dir], ", installed under ", dir, "\\n" );
		}
		info = chomp( info );
	}
	log_message( port: port, data: info );
	exit( 0 );
}
exit( 0 );

