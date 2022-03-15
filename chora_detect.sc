if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13849" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Chora Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects whether the remote host is running Chora and
  extracts version numbers and locations of any instances found.

  Chora is a PHP-based interface to CVS repositories from the Horde
  Project." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.horde.org/chora/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
installs = 0;
files = make_list( "/horde/services/help/?module=chora&show=about",
	 "/cvs.php",
	 "/README" );
for dir in nasl_make_list_unique( "/horde/chora", "/chora", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		res = http_get_cache( item: dir + file, port: port );
		if(!res){
			continue;
		}
		if(egrep( string: res, pattern: "^HTTP/1\\.[01] 200" )){
			if( file == "/horde/services/help/?module=chora&show=about" ){
				pat = ">This is Chora +(.+).<";
			}
			else {
				if( IsMatchRegexp( file, "^/cvs.php" ) ){
					pat = "class=.+>CHORA +(.+)</a>";
				}
				else {
					if( file == "/README" ){
						pat = "^Version +(.+) *$";
					}
					else {
						exit( 0 );
					}
				}
			}
			matches = egrep( pattern: pat, string: res );
			for match in split( matches ) {
				if(file == "/README" && !ContainsString( res, "Chora" )){
					continue;
				}
				match = chomp( match );
				ver = eregmatch( pattern: pat, string: match );
				if(isnull( ver )){
					break;
				}
				ver = ver[1];
				set_kb_item( name: "chora/detected", value: TRUE );
				installations[install] = ver;
				++installs;
				cpe = build_cpe( value: ver, exp: "^([0-9.]+)", base: "cpe:/a:horde:chora:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:horde:chora";
				}
				register_product( cpe: cpe, location: install, port: port, service: "www" );
				break;
			}
			if(installs){
				break;
			}
		}
	}
}
if(installs){
	if( installs == 1 ){
		for dir in keys( installations ) {
			}
		info = "Chora " + ver + " was detected on the remote host under the path " + dir + ".";
	}
	else {
		info = "Multiple instances of Chora were detected on the remote host:\n\n";
		for dir in keys( installations ) {
			info += NASLString( "    ", installations[dir], ", installed under ", dir, "\\n" );
		}
		info = chomp( info );
	}
	log_message( port: port, data: info );
}
exit( 0 );

