if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900338" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PHP-Nuke Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed PHP-Nuke version." );
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
cgidirs = nasl_make_list_unique( "/php-nuke", "/phpnuke", "/", "/nuke", http_cgi_dirs( port: port ) );
subdirs = make_list( "/",
	 "/html" );
for cgidir in cgidirs {
	for subdir in subdirs {
		if(cgidir == "/cgi-bin" && subdir == "/cgi-bin"){
			continue;
		}
		if(cgidir != "/" && subdir == "/"){
			subdir = "";
		}
		if(cgidir == "/"){
			cgidir = "";
		}
		dirs = nasl_make_list_unique( dirs, cgidir + subdir );
	}
}
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	rcvRes1 = http_get_cache( item: dir + "/admin.php", port: port );
	if(( IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) || IsMatchRegexp( rcvRes1, "^HTTP/1\\.[01] 200" ) ) && ( ContainsString( rcvRes, "PHP-Nuke Powered Site" ) || ContainsString( rcvRes, "<p class=\"copy\">PHPNUKE" ) || ContainsString( rcvRes, "PHP-Nuke</a> Copyright" ) || ContainsString( rcvRes, "<a href=\"http://phpnuke.org/\">" ) || ContainsString( rcvRes1, "PHP-Nuke Powered Site" ) || ContainsString( rcvRes1, "<p class=\"copy\">PHPNUKE" ) || ContainsString( rcvRes1, "PHP-Nuke</a> Copyright" ) || ContainsString( rcvRes1, "<a href=\"http://phpnuke.org/\">" ) )){
		version = "unknown";
		for path in make_list( "/../Changes.txt",
			 "/Changes.txt",
			 "/CHANGES",
			 "/../CHANGES" ) {
			sndReq = http_get( item: dir + path, port: port );
			rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
			if(ContainsString( rcvRes, "PHP-Nuke" ) && ContainsString( rcvRes, "Version" )){
				ver = eregmatch( pattern: "Version ([0-9.]+)", string: rcvRes );
				if(ver[1] != NULL){
					version = ver[1];
					break;
				}
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/php-nuke", value: tmp_version );
		set_kb_item( name: "php-nuke/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:phpnuke:php-nuke:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:phpnuke:php-nuke";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PHP-Nuke", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

