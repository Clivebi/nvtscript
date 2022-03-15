if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106004" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SysAid Help Desk Detection" );
	script_tag( name: "summary", value: "Detection of SysAid Help Desk Software

  The script sends a connection request to the server and attempts to detect SysAid Help Desk Software." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/sysaid", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/Login.jsp";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "SysAid Help Desk" ) || ContainsString( buf, "Software del Servicio de asistencia de SysAid" ) || ContainsString( buf, "class=\"LookLikeLink\"> by SysAid" ) )){
		version = "unknown";
		url = dir + "/errorInSignUp.htm";
		req = http_get( port: port, item: url );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		vers = eregmatch( string: buf, pattern: "css/master.css\\?v([0-9.]+)", icase: TRUE );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		set_kb_item( name: "sysaid/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sysaid:sysaid:" );
		if(!cpe){
			cpe = "cpe:/a:sysaid:sysaid";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SysAid Help Desktop Software", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

