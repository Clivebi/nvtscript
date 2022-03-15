if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100752" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Nagios XI Detection" );
	script_tag( name: "summary", value: "Detection of installed path and version of
  Nagios XI.

  The script sends HTTP GET requests and tries to confirm the Nagios XI installation." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/nagiosxi", "/nagios", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "Set-Cookie: nagiosxi", string: buf, icase: TRUE ) && ContainsString( buf, "Nagios Enterprises" ) && ( ContainsString( buf, "Nagios XI - Login" ) || ContainsString( buf, ">Nagios XI<" ) )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "footernotice\">Nagios XI (20[0-9]{2}[^ ]+)", icase: TRUE );
		if( !isnull( version[1] ) ){
			vers = chomp( version[1] );
		}
		else {
			version = eregmatch( string: buf, pattern: "name=\"version\" value=\"(([0-9.]+)|(20[0-9]{2}[^ ]+))\">" );
			if(!isnull( version[1] )){
				vers = chomp( version[1] );
			}
		}
		set_kb_item( name: NASLString( "www/", port, "/nagiosxi" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "nagiosxi/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "([0-9.]+)|(20[0-9]{2}[^ ]+)", base: "cpe:/a:nagios:nagiosxi:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:nagios:nagiosxi:";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Nagios XI", version: vers, install: install, cpe: cpe, concluded: vers ), port: port );
	}
}
exit( 0 );

