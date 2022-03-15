if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12214" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1934" );
	script_bugtraq_id( 10156 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "File Inclusion Vulnerability in Gemitel" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version or disable this CGI altogether." );
	script_tag( name: "summary", value: "A vulnerability in Gimtel allows a remote attacker to execute
  arbitrary commands on this host." );
	script_tag( name: "affected", value: "GEMITEL v3.50. Other versions might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/gimtel", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/html/affich.php?base=http://xxx.xxxxxx./";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	if(egrep( pattern: "http://xxx\\.xxxxxx\\./sp-turn\\.php", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

