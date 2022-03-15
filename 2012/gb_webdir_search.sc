if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103437" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-27 16:32:37 +0100 (Mon, 27 Feb 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Search for specified dirs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "find_service.sc", "httpver.sc", "no404.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This Plugin is searching for the specified webdirs." );
	script_add_preference( name: "Search for dir(s)", value: "/admin;/manager", type: "entry", id: 1 );
	script_add_preference( name: "Valid http status codes indicating that a directory was found", value: "200;301;302;401;403", type: "entry", id: 2 );
	script_add_preference( name: "Run this Plugin", type: "checkbox", value: "no", id: 3 );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
run = script_get_preference( name: "Run this Plugin", id: 3 );
if(!ContainsString( run, "yes" )){
	exit( 0 );
}
search_dirs = script_get_preference( name: "Search for dir(s)", id: 1 );
http_codes = script_get_preference( name: "Valid http status codes indicating that a directory was found", id: 2 );
dirs = split( buffer: search_dirs, sep: ";", keep: FALSE );
if(max_index( dirs ) < 1){
	exit( 0 );
}
codes = split( buffer: http_codes, sep: ";", keep: FALSE );
if(max_index( codes ) < 1){
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
if(http_is_cgi_scan_disabled()){
	log_message( port: 0, data: "Plugin was enabled but CGI Scanning was disabled via Scan Config, not running this test." );
	exit( 0 );
}
func check_response( resp, codes ){
	var resp, code, codes;
	for code in codes {
		if(!isnull( code )){
			if(ereg( pattern: "^HTTP/1\\.[01] " + code, string: resp )){
				return TRUE;
			}
		}
	}
	return FALSE;
}
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
if(http_get_no404_string( port: port, host: host )){
	exit( 0 );
}
for dir in dirs {
	dir = chomp( dir );
	if(!ereg( pattern: "^/", string: dir )){
		dir = "/" + dir;
	}
	req = http_get( item: dir, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf || IsMatchRegexp( buf, "^HTTP/1\\.[01] 404" )){
		continue;
	}
	if(check_response( resp: buf, codes: codes )){
		report += "Found dir " + dir + "\n";
	}
}
if(report){
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

