if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10403" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1178 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2000-0381" );
	script_name( "DBMan CGI server information leakage" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 SecuriTeam" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version" );
	script_tag( name: "summary", value: "It is possible to cause the DBMan
  CGI to reveal sensitive information, by requesting a URL such as:

  GET /scripts/dbman/db.cgi?db=no-db" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
req = http_get( item: "/scripts/dbman/db.cgi?db=no-db", port: port );
result = http_send_recv( port: port, data: req );
backup = result;
report = NASLString( "\\nIt is possible to cause the DBMan\\nCGI to reveal sensitive information, by requesting a URL such as:\\n\\n", "GET /scripts/dbman/db.cgi?db=no-db\\n\\nthe following could be obtained: \\n\\n" );
if(ContainsString( result, "CGI ERROR" )){
	result = strstr( backup, NASLString( "name: no-db at " ) );
	result = result - strstr( result, NASLString( " line " ) );
	result = result - "name: no-db at ";
	report = "CGI full path is at: " + result + NASLString( "\\n" );
	result = strstr( backup, NASLString( "Perl Version        : " ) );
	result = result - strstr( result, NASLString( "\\n" ) );
	result = result - NASLString( "Perl Version        : " );
	report = report + "Perl version: " + result + NASLString( "\\n" );
	result = strstr( backup, NASLString( "PATH                : " ) );
	result = result - strstr( result, NASLString( "\\n" ) );
	result = result - NASLString( "PATH                : " );
	report = report + "Server path: " + result + NASLString( "\\n" );
	result = strstr( backup, NASLString( "SERVER_ADDR         : " ) );
	result = result - strstr( result, NASLString( "\\n" ) );
	result = result - NASLString( "SERVER_ADDR         : " );
	report = report + "Server real IP: " + result + NASLString( "\\n" );
	result = strstr( backup, NASLString( "SERVER_SOFTWARE     : " ) );
	result = result - strstr( result, NASLString( "\\n" ) );
	result = result - NASLString( "SERVER_SOFTWARE     : " );
	report = report + "Server software: " + result + NASLString( "\\n" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

