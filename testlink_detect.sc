if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100389" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-10 18:09:58 +0100 (Thu, 10 Dec 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "TestLink Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of TestLink.

  The script sends a connection request to the server and attempts to extract the version number from the reply." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/testlink", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(( egrep( pattern: "<title>TestLink( - Login)?</title>", string: buf, icase: TRUE ) && ( egrep( pattern: "TestLink is licensed under the", string: buf ) || egrep( pattern: "Please log in", string: buf ) ) ) || ( ContainsString( buf, "for=\"tl_password\">" ) && ContainsString( buf, "for=\"tl_login\">" ) )){
		version = "unknown";
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		url = dir + "/CHANGELOG";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: "Test[Ll]ink (- )?([0-9.]+)", string: res, icase: FALSE );
		if( !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) || isnull( vers[2] ) ){
			vers = eregmatch( string: buf, pattern: "TestLink[Prague ]{0,7} ([0-9.]+)", icase: TRUE );
			if(isnull( vers[1] )){
				vers = eregmatch( string: buf, pattern: "<br[ ]?/>([0-9.]+) \\([A-Za-z]+\\)</p>", icase: TRUE );
			}
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		else {
			version = vers[2];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		set_kb_item( name: "testlink/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:testlink:testlink:" );
		if(!cpe){
			cpe = "cpe:/a:testlink:testlink";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "TestLink", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

