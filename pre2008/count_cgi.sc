if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10049" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 128 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0021" );
	script_name( "Count.cgi" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to wwwcount 2.4 or later." );
	script_tag( name: "summary", value: "An old version of 'Count.cgi' cgi is installed.
  It has a well known security flaw that lets anyone execute arbitrary
  commands with the privileges of the http daemon (root, www, nobody...)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = strcat( dir, "/Count.cgi?align=topcenter" );
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	res = strstr( res, "Count.cgi " );
	if(res && ereg( string: res, pattern: ".*Count\\.cgi +([01]\\.[0-9]+|2\\.[0-3]+)" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

