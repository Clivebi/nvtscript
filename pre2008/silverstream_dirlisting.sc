if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10846" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "SilverStream directory listing" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Tor Houghton" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://online.securityfocus.com/archive/101/144786" );
	script_tag( name: "solution", value: "Reconfigure the server so that others
  cannot view directory listings." );
	script_tag( name: "summary", value: "SilverStream directory listings are enabled." );
	script_tag( name: "impact", value: "An attacker may use this problem to gain more
  knowledge on this server and possibly to get files you would want to hide." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/SilverStream";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(( egrep( pattern: "<html><head><title>.*SilverStream.*</title>", string: res ) ) && ( ContainsString( res, "/Pages" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

