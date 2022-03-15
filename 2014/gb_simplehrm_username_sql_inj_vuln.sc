if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804531" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-2498" );
	script_bugtraq_id( 59254 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-04-03 10:35:41 +0530 (Thu, 03 Apr 2014)" );
	script_name( "SimpleHRM 'username' Parameter SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with SimpleHRM and is prone to sql injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the /index.php/user/setLogin script not properly sanitizing
  user-supplied input to the 'username' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "SimpleHRM version 2.3 and 2.2, Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24954" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2013/04/17/1" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
host = http_host_name( port: http_port );
for dir in nasl_make_list_unique( "/", "/simplehrm", "/hrm", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, "SimpleHRM<" )){
		url = dir + "/index.php/user/setLogin";
		postData = "username=%27SQL-Injection-Test&password=abcdef";
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq, bodyonly: TRUE );
		if(rcvRes && IsMatchRegexp( rcvRes, "Execute Error: You have an error in your SQL syntax.*SQL-Injection-Test" ) && ContainsString( rcvRes, ">SimpleHRM" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

