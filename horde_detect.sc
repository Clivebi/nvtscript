if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15604" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Horde Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.horde.org/" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract
  the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_no404_string( port: port, host: host )){
	exit( 0 );
}
dirs = nasl_make_list_unique( http_cgi_dirs( port: port ), "/horde", "/" );
for dir in dirs {
	files = make_list( "/services/help/?module=horde&show=menu",
		 "/services/help/?module=horde&show=about",
		 "/test.php",
		 "/lib/version.phps",
		 "/status.php3" );
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		req = http_get( item: NASLString( dir, file ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(egrep( string: res, pattern: "^HTTP/1\\.[01] 200" )){
			if( IsMatchRegexp( file, "^/services/help" ) ){
				if(ContainsString( file, "about" )){
					pat = ">This is Horde (.+).</h2>";
				}
				if(ContainsString( file, "menu" )){
					pat = ">Horde ([0-9.]+[^<]*)<";
				}
			}
			else {
				if( file == "/test.php" ){
					pat = "^ *<li>horde: +(.+) *</li> *$";
				}
				else {
					if( file == "/lib/version.phps" ){
						pat = "HORDE_VERSION', '(.+)'";
					}
					else {
						if( file == "/status.php3" ){
							pat = ">Horde, Version (.+)<";
						}
						else {
							exit( 1 );
						}
					}
				}
			}
			version = "unknown";
			vers = eregmatch( pattern: pat, string: res );
			if(!vers){
				continue;
			}
			if(!isnull( vers[1] )){
				version = vers[1];
				concUrl = file;
			}
			set_kb_item( name: "horde/installed", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:horde:horde_groupware:" );
			if(!cpe){
				cpe = "cpe:/a:horde:horde_groupware";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Horde", version: version, install: install, cpe: cpe, concluded: version, concludedUrl: concUrl ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

