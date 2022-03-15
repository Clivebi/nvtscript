if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146181" );
	script_version( "2021-06-28T11:17:55+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:17:55 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-28 08:47:02 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Online Grades Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Online Grades." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://sourceforge.net/projects/onlinegrades/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/grades", "/onlinegrades", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "HTTP/1\\.[01] 200" )){
		continue;
	}
	if(egrep( string: res, pattern: "\" content=\"Online Grade(s Version|s for LCS| Posting System)", icase: FALSE ) || ContainsString( res, "alt=\"Powered by Online Grades\"/>" )){
		version = "unknown";
		vers = eregmatch( pattern: "Online Grades Version(:)?\\s*([0-9.]+)", string: res );
		if(!isnull( vers[2] )){
			version = vers[2];
		}
		set_kb_item( name: "online_grades/detected", value: TRUE );
		set_kb_item( name: "online_grades/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:onlinegrades:online_grades:" );
		if(!cpe){
			cpe = "cpe:/a:onlinegrades:online_grades";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Online Grades", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

