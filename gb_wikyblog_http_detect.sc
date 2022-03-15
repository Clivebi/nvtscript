if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146646" );
	script_version( "2021-09-07T05:45:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 05:45:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-06 14:17:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WikyBlog Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of WikyBlog." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.wikyblog.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/blog", "/Wiky", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( port: port, item: url );
	if(ContainsString( res, "<span>Powered by <a href=\"http://www.wikyblog.com\"" ) && ContainsString( res, ">WikyBlog<" )){
		version = "unknown";
		set_kb_item( name: "wikyblog/detected", value: TRUE );
		set_kb_item( name: "wikyblog/http/detected", value: TRUE );
		cpe = "cpe:/a:wikyblog:wikyblog";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "WikyBlog", version: version, install: install, cpe: cpe ), port: port );
		exit( 0 );
	}
}
exit( 0 );

