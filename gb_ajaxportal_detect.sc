if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800816" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "AjaxPortal Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of AjaxPortal." );
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
for dir in nasl_make_list_unique( "/", "/ajaxportal", "/portal", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( rcvRes, "<title>Ajax Portal-[Help|Myio] | Welcome  </title>" )){
		version = "unknown";
		ver = eregmatch( pattern: "Ajax Portal ([0-9]\\.[0-9]+)", string: rcvRes );
		if(ver[1] != NULL){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/AjaxPortal", value: tmp_version );
		set_kb_item( name: "ajaxportal/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:myiosoft.com:ajaxportal:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:myiosoft.com:ajaxportal";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Ajax Portal", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

