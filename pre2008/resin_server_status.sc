if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11930" );
	script_version( "2021-02-26T10:28:36+0000" );
	script_tag( name: "last_modification", value: "2021-02-26 10:28:36 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Resin /caucho-status accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 StrongHoldNet" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "If you don't use this feature, set the content of the '<caucho-status>' element
  to 'false' in the resin.conf file." );
	script_tag( name: "summary", value: "Requesting the URI /caucho-status gives information about
  the currently running Resin java servlet container." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/caucho-status";
r = http_get_cache( item: url, port: port );
if(!r){
	exit( 0 );
}
if(ContainsString( r, "<title>Status : Caucho Servlet Engine" ) && ContainsString( r, "%cpu/thread" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

