if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100061" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-19 11:22:36 +0100 (Thu, 19 Mar 2009)" );
	script_name( "Mantis Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/" );
	script_tag( name: "summary", value: "Detects the installed version of
  Mantis a free popular web-based bugtracking system.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
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
for dir in nasl_make_list_unique( "/mantis", "/mantisbt", "/bugs", "/bugtracker", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login_page.php";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "Copyright &copy;.*Mantis Group", string: buf ) || egrep( pattern: ".*Powered by Mantis Bugtracker.*", string: buf ) || egrep( pattern: ".*Powered by.*>MantisBT.*", string: buf ) || egrep( pattern: ".*Mantis Bugtracker", string: buf ) || egrep( pattern: "Copyright &copy;.*MantisBT Team", string: buf ) || egrep( pattern: "Copyright &copy;.*MantisBT Group", string: buf ) || ContainsString( buf, "\" title=\"MantisBT: " ) || ContainsString( buf, "/css/ace-mantis.css\" />" ) || ContainsString( buf, "/images/mantis_logo.png\">" )){
		version = "unknown";
		vers = eregmatch( string: buf, pattern: ".*Mantis ([0-9]+\\.+[0-9]*\\.*[0-9]*[a-zA-Z0-9]*).*" );
		if(!vers[1]){
			vers = eregmatch( string: buf, pattern: ">MantisBT ([0-9.]+)" );
		}
		if(!vers[1]){
			vers = eregmatch( string: buf, pattern: ">MantisBT  ([0-9.]+(-[a-z0-9.]+)?)" );
		}
		if(vers[1]){
			version = vers[1];
			concluded = version;
		}
		if(version == "unknown"){
			url = dir + "/doc/RELEASE";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			vers = eregmatch( string: buf, pattern: "([0-9.]+(-[a-z0-9.]+)?) (Maintenance|Stable|Security) Release" );
			if( IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && vers[1] ){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				concluded = vers[0];
			}
			else {
				url = dir + "/doc/en-US/Developers_Guide/Developers_Guide.txt";
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				vers = eregmatch( string: buf, pattern: "Release ([0-9.]+(-[a-z0-9.]+)?)" );
				if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && vers[1]){
					version = vers[1];
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
					concluded = vers[0];
				}
			}
		}
		set_kb_item( name: "mantisbt/detected", value: TRUE );
		if( IsMatchRegexp( version, "^([0-9.]+-[a-zA-Z0-9.]+)" ) ){
			cpe = build_cpe( value: version, exp: "([0-9.]+-[a-zA-Z0-9.]+)", base: "cpe:/a:mantisbt:mantisbt:" );
		}
		else {
			if( IsMatchRegexp( version, "^([0-9.]+[a-zA-Z0-9.]+)" ) ){
				cpe = build_cpe( value: version, exp: "([0-9.]+[a-zA-Z0-9.]+)", base: "cpe:/a:mantisbt:mantisbt:" );
			}
			else {
				cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:mantisbt:mantisbt:" );
			}
		}
		if(!cpe){
			cpe = "cpe:/a:mantisbt:mantisbt";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Mantis BugTracker", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: concluded ), port: port );
	}
}
exit( 0 );

