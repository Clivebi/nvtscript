if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11959" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Remote Code Execution in Knowledge Builder" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version or disable this CGI altogether." );
	script_tag( name: "summary", value: "KnowledgeBuilder is a feature-packed knowledge base solution CGI suite.

  A vulnerability in this product may allow a remote attacker to execute
  arbitrary commands on this host." );
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
for path in nasl_make_list_unique( "/kb", http_cgi_dirs( port: port ) ) {
	if(path == "/"){
		path = "";
	}
	url = path + "/index.php?page=http://xxxxxxxxxxxxx/vt-test";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		continue;
	}
	find = NASLString( "operation error" );
	find_alt = NASLString( "getaddrinfo failed" );
	if(ContainsString( res, find ) || ContainsString( res, find_alt )){
		req = http_get( item: path + "/index.php?page=index.php", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(!res){
			continue;
		}
		if(ContainsString( res, find ) || ContainsString( res, find_alt )){
			continue;
		}
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

