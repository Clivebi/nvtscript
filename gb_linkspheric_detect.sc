if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801112" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "linkSpheric Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of linkSpheric." );
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
for dir in nasl_make_list_unique( "/linkSpheric", "/Spheric", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/admin/index.php", port: port );
	rcvRes2 = http_get_cache( item: dir + "/index.php", port: port );
	if(( IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes, "generator\" content=\"linkSpheric" ) || ( ContainsString( rcvRes, "Powered by" ) && ContainsString( rcvRes, "S</span>pheric" ) ) ) ) || ( IsMatchRegexp( rcvRes2, "^HTTP/1\\.[01] 200" ) && ( ContainsString( rcvRes2, "generator\" content=\"linkSpheric" ) || ( ContainsString( rcvRes2, "Powered by" ) && ContainsString( rcvRes2, "S</span>pheric" ) ) ) )){
		version = eregmatch( pattern: "linkSpheric version ([0-9.]+( Beta [0-9.])?)", string: rcvRes, icase: 1 );
		if(isnull( version )){
			sndReq = http_get( item: dir + "/CHANGELOG", port: port );
			rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
			version = egrep( pattern: "version [0-9.]+[a-z0-9 ]+(release)", string: rcvRes, icase: 1 );
			version = eregmatch( pattern: "version ([0-9.]+( Beta [0-9])?)", string: version, icase: 1 );
		}
		spheric_ver = ereg_replace( pattern: " ", replace: ".", string: version[1] );
		if( !isnull( spheric_ver ) ){
			version = spheric_ver;
		}
		else {
			version = "unknown";
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/linkSpheric", value: tmp_version );
		set_kb_item( name: "linkspheric/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)\\.([0-9a-zA-Z.]+)", base: "cpe:/a:dataspheric:linkspheric:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:dataspheric:linkspheric";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "linkSpheric", version: version, install: install, cpe: cpe, concluded: spheric_ver ), port: port );
	}
}
exit( 0 );

