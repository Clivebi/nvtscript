if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804737" );
	script_version( "2021-03-11T10:58:32+0000" );
	script_cve_id( "CVE-2014-5082", "CVE-2014-5192", "CVE-2014-5193" );
	script_bugtraq_id( 69019, 68985 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-08-25 13:06:02 +0530 (Mon, 25 Aug 2014)" );
	script_name( "Sphider Multiple Vulnerabilities - Aug14" );
	script_tag( name: "summary", value: "Sphider is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the
  response." );
	script_tag( name: "insight", value: "The flaw is due to the /sphider/admin/admin.php script
  not properly sanitizing user-supplied input to the 'site_id', 'url', 'filter', and
  'category' parameters." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to
  execute arbitrary HTML and script code and SQL statements on the vulnerable system,
  which may lead to access or modify data in the underlying database." );
	script_tag( name: "affected", value: "Sphider version 1.3.6 and earlier." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34238" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127720" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
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
for dir in nasl_make_list_unique( "/", "/sphider", "/search", "/webspider", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/admin/admin.php", port: port );
	if(ContainsString( res, ">Sphider" )){
		url = dir + "/admin/admin.php";
		postData = "user=foo&pass=bar&f=20&site_id=1'SQL-Injection-Test";
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(res && IsMatchRegexp( res, "You have an error in your SQL syntax.*SQL-Injection-Test" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

