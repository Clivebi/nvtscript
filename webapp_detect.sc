if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102009" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-09-18 16:06:42 +0200 (Fri, 18 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WebAPP Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 LSS" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.web-app.org/" );
	script_tag( name: "summary", value: "The remote host is running WebAPP, an open source web portal written
  in Perl." );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	ver = "unknown";
	found = 0;
	res = http_get_cache( item: dir + "/", port: port );
	pat = "<meta name=.Generator. content=.WebAPP[^0-9]*([^>\"]*)";
	match = egrep( pattern: pat, string: res, icase: TRUE );
	if(match){
		item = eregmatch( pattern: pat, string: match, icase: TRUE );
		ver = item[1];
		found = 1;
	}
	if(!ver){
		pat = "This site was made with[^>]*>WebAPP([^>]*>)*[^>]*>v([0-9.]*)";
		item = eregmatch( pattern: pat, string: res, icase: TRUE );
		if(item){
			ver = item[2];
			found = 1;
		}
	}
	if(found){
		tmp_version = ver + " under " + install;
		set_kb_item( name: "www/" + port + "/webapp", value: tmp_version );
		set_kb_item( name: "WebAPP/installed", value: TRUE );
		cpe = build_cpe( value: ver, exp: "^([0-9.]+)", base: "cpe:/a:web_app.net:webapp:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:web_app.net:webapp";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "WebAPP", version: ver, install: install, cpe: cpe, concluded: ver ), port: port );
	}
}
exit( 0 );

