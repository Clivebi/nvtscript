if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806900" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-16 11:04:52 +0530 (Wed, 16 Dec 2015)" );
	script_name( "zTree Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of installed version
  of zTree.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
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
for dir in nasl_make_list_unique( "/", "/zTree", "/zTree/demo", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/en/index.html", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "class=\"ztree\"" )){
		req2 = eregmatch( pattern: "/js/jquery.ztree.core-([0-9.]+).js", string: res );
		if(!req2[0]){
			continue;
		}
		url = dir + req2[0];
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		version = "unknown";
		ver = eregmatch( pattern: "JQuery zTree core v([0-9.]+)", string: res );
		if(ver[1]){
			version = ver[1];
		}
		set_kb_item( name: "www/" + port + "/zTree", value: version );
		set_kb_item( name: "zTree/Installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ztree_project:ztree:" );
		if(!cpe){
			cpe = "cpe:/a:ztree_project:ztree";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "zTree", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

