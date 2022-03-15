if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12647" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SquirrelMail Detection" );
	script_tag( name: "summary", value: "Detection of SquirrelMail.

The script sends a connection request to the server and attempts to detect SquirrelMail and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.squirrelmail.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/squirrelmail", "/squirrel", "/webmail", "/mail", "/sm", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/src/login.php";
	res = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( res, "<title>Squirrel[mM]ail - Login</title>" ) || ContainsString( res, "squirrelmail_loginpage_onload" )){
		version = "unknown";
		files = make_array( "/src/login.php", "SquirrelMail [vV]ersion ([0-9.]+)", "/src/compose.php", "SquirrelMail [vV]ersion ([0-9.]+)<BR", "/src/configtest.php", "SquirrelMail version:</td><td><b>([0-9.]+)", "/doc/ChangeLog", "Version ([0-9.]+) - [0-9]", "/doc/ReleaseNotes", "Release Notes: SquirrelMail ([0-9.]+)" );
		for file in keys( files ) {
			res = http_get_cache( port: port, item: dir + file );
			vers = eregmatch( pattern: files[file], string: res );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "squirrelmail/version", value: version );
				concurl = dir + file;
				break;
			}
		}
		set_kb_item( name: "squirrelmail/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:squirrelmail:squirrelmail:" );
		if(!cpe){
			cpe = "cpe:/a:squirrelmail:squirrelmail";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SquirrelMail", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concurl ), port: port );
	}
}
exit( 0 );

