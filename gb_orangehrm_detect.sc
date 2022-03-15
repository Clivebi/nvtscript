if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100850" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OrangeHRM Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.orangehrm.com/" );
	script_tag( name: "summary", value: "This host is running OrangeHRM, a Human Resource management and
  development system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/orangehrm", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for page in nasl_make_list_unique( "/login.php", "/", "/symfony/web/index.php/auth/login" ) {
		url = dir + page;
		buf = http_get_cache( item: url, port: port );
		if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			continue;
		}
		if(( ContainsString( buf, "<title>OrangeHRM" ) && ContainsString( buf, "&copy; OrangeHRM Inc." ) && ContainsString( buf, "Login Name :" ) ) || ( IsMatchRegexp( buf, "<title>[^<]*OrangeHRM" ) && ( ContainsString( buf, ">OrangeHRM, Inc<" ) || ContainsString( buf, "//www.orangehrm.com" ) || ContainsString( buf, "js/orangehrm.validate.js" ) || ContainsString( buf, "OrangeHRM on " ) ) )){
			vers = "unknown";
			version = eregmatch( string: buf, pattern: "OrangeHRM</a> ver ([0-9.]+)", icase: TRUE );
			if(version[1]){
				vers = chomp( version[1] );
			}
			if(vers == "unknown"){
				version = eregmatch( string: buf, pattern: "(Orange| )HRM ([0-9.]+)<", icase: TRUE );
				if(version[2]){
					vers = version[2];
				}
			}
			set_kb_item( name: "www/" + port + "/orangehrm", value: vers + " under " + install );
			set_kb_item( name: "orangehrm/detected", value: TRUE );
			cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:orangehrm:orangehrm:" );
			if(!cpe){
				cpe = "cpe:/a:orangehrm:orangehrm";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OrangeHRM", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

