if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807791" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-18 12:45:32 +0530 (Mon, 18 Apr 2016)" );
	script_name( "BigTree CMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether BigTree CMS is present on the
  target system and if so, tries to figure out the installed version." );
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
for dir in nasl_make_list_unique( "/", "/BigTree", "/cms", "/bigtree", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( dir + "/site/index.php/admin/login/",
		 dir + "/admin/login/" ) {
		res = http_get_cache( item: url, port: port );
		if(!res){
			continue;
		}
		if(( ContainsString( res, "<title>BigTree Site Login</title>" ) && ContainsString( res, "<label>Password</label>" ) ) || IsMatchRegexp( res, "<a href=\"https?://(www\\.)?bigtreecms\\.(com|org)\" class=\"login_logo\"" )){
			vers = "unknown";
			version = eregmatch( pattern: "Version ([0-9.]+)", string: res );
			if(version[1]){
				vers = version[1];
			}
			set_kb_item( name: "bigtree_cms/detected", value: TRUE );
			cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:bigtreecms:bigtree_cms:" );
			if(!cpe){
				cpe = "cpe:/a:bigtreecms:bigtree_cms";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "BigTree CMS", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		}
	}
}
exit( 0 );

