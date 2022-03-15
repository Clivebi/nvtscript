if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113169" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-05-03 16:40:00 +0200 (Thu, 03 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "GPON Home Router Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 81, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "GPON Home Router Detection." );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/login.html" );
res2 = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( res, "<form id=\"XForm\" name=\"XForm\" method=\"post\" action=\"/GponForm/LoginForm\">" ) || IsMatchRegexp( res, "var XOntName = \'GPON Home Gateway\';" ) || ( IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ( IsMatchRegexp( res2, "<title>.*GPON Home Gateway.*</title>" ) || IsMatchRegexp( res2, "<td colspan.*GPON Home Gateway.*</td>" ) ) )){
	set_kb_item( name: "gpon/home_router/detected", value: TRUE );
	cpe = "cpe:/o:gpon:home_router_firmware";
	os_register_and_report( os: "GPON Home Router Firmware", cpe: cpe, desc: "GPON Home Router Detection", runs_key: "unixoide" );
	register_and_report_cpe( app: "GPON Home Router", cpename: cpe, insloc: "/", regService: "www", regPort: port );
}
exit( 0 );

