if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900904" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Admin News Tools Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of Admin News Tool." );
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
for dir in nasl_make_list_unique( "/ant", "/Ant", "/ANT", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for file in make_list( "/news/admin/index.php",
		 "/Lisez%20moi.txt",
		 "/Readme.txt" ) {
		sndReq = http_get( item: dir + file, port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Admin News Tools" )){
			version = "unknown";
			ver = eregmatch( pattern: "Admin News Tools v([0-9.]+)", string: rcvRes );
			if(ver[1] != NULL){
				version = ver[1];
			}
			tmp_version = version + " under " + install;
			set_kb_item( name: "www/" + port + "/Admin-New-Tools", value: tmp_version );
			set_kb_item( name: "ANT/installed", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:adminnewstools:admin_news_tools:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:adminnewstools:admin_news_tools";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Admin News Tools", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		}
	}
}
exit( 0 );

