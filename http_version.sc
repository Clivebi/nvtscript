if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10107" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "HTTP Server type and version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 H. Scholz & Contributors" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_add_preference( name: "Show full HTTP headers in output", type: "checkbox", value: "no", id: 1 );
	script_tag( name: "summary", value: "This script detects and reports the HTTP Server's banner
  which might provide the type and version of it." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
show_headers = script_get_preference( name: "Show full HTTP headers in output", id: 1 );
report = "The remote HTTP Server banner is:\n\n";
port = http_get_port( default: 80 );
headers = http_get_remote_headers( port: port, ignore_broken: TRUE );
if(!headers || !IsMatchRegexp( headers, "^HTTP/(0\\.9|1\\.[01]|2) +[0-9]{3}" )){
	exit( 0 );
}
serverbanner = egrep( pattern: "^(DAAP-)?Server\\s*:", string: headers, icase: TRUE );
if(!serverbanner){
	exit( 0 );
}
serverbanner = chomp( serverbanner );
report += serverbanner;
if(show_headers == "yes"){
	report += "\n\nFull HTTP headers:\n\n" + headers;
}
log_message( port: port, data: report );
exit( 0 );

