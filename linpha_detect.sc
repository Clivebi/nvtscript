if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100119" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)" );
	script_name( "LinPHA Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  LinPHA, a photo/image archive/album/gallery written in PHP.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_xref( name: "URL", value: "http://linpha.sourceforge.net" );
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
for dir in nasl_make_list_unique( "/", "/linpha", "/image", "/album", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(isnull( buf )){
		continue;
	}
	if(( egrep( pattern: "LinPHA Version [0-9.]+", string: buf, icase: TRUE ) && egrep( pattern: "The LinPHA developers", string: buf, icase: TRUE ) ) || IsMatchRegexp( buf, "LinPHA  [0-9.]+" )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "LinPHA (Version)? ([0-9.]+)", icase: TRUE );
		if(!isnull( version[2] )){
			vers = version[2];
		}
		set_kb_item( name: "linpha/detected", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:linpha:linpha:" );
		if(!cpe){
			cpe = "cpe:/a:linpha:linpha";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "LinPHA", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

