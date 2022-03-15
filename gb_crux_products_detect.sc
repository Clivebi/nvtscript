if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801381" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)" );
	script_name( "CruxSoftware Products Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running
  CruxSoftware Products version." );
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
for dir in nasl_make_list_unique( "/CruxCMS", "/CruxCMS300/manager", "/cms", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/login.php", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 404" )){
		res = http_get_cache( item: dir + "/index.php", port: port );
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Crux CMS<" )){
		for filename in make_list( "/../Docs/ReadMe.txt",
			 "/../Docs/ChangeLog.txt",
			 "/Docs/ChangeLog.txt",
			 "/Docs/ReadMe.txt" ) {
			res = http_get_cache( item: dir + filename, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "CruxCMS" )){
				cmsVer = eregmatch( pattern: "Version ([0-9.]+)", string: res );
				if(cmsVer[1] != NULL){
					tmp_version = cmsVer[1] + " under " + install;
					set_kb_item( name: "www/" + port + "/CruxCMS", value: tmp_version );
					set_kb_item( name: "cruxcms/detected", value: TRUE );
					register_and_report_cpe( app: "CruxCMS", ver: cmsVer[1], base: "cpe:/a:cruxsoftware:cruxcms:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www" );
				}
			}
			break;
		}
	}
}
for dir in nasl_make_list_unique( "/CruxPA200", "/CruxPA200/Manager", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/login.php", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "CruxPA" )){
		for filename in make_list( "/../Docs/ReadMe.txt",
			 "/../Docs/ChangeLog.txt",
			 "/Docs/ChangeLog.txt",
			 "/Docs/ReadMe.txt" ) {
			res = http_get_cache( item: dir + filename, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "CruxPA" )){
				cmspaVer = eregmatch( pattern: "Version ([0-9.]+)", string: res );
				if(cmspaVer[1] != NULL){
					tmp_version = cmspaVer[1] + " under " + install;
					set_kb_item( name: "www/" + port + "/CruxPA", value: tmp_version );
					set_kb_item( name: "cruxpa/detected", value: TRUE );
					register_and_report_cpe( app: "CruxPA", ver: cmspaVer[1], base: "cpe:/a:cruxsoftware:cruxpa:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www" );
				}
			}
			break;
		}
	}
}
exit( 0 );

