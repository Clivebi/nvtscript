CPE = "cpe:/a:php-fusion:php-fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803431" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2013-1803", "CVE-2013-1804", "CVE-2013-1805", "CVE-2013-1806", "CVE-2013-1807", "CVE-2013-7375" );
	script_bugtraq_id( 58226, 58265, 58270 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-07 13:36:54 +0530 (Thu, 07 Mar 2013)" );
	script_name( "PHP-Fusion Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "php-fusion/detected" );
	script_xref( name: "URL", value: "http://secunia.com/52403" );
	script_xref( name: "URL", value: "http://secunia.com/52226" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Feb/149" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24562" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120598/PHP-Fusion-7.02.05-XSS-LFI-SQL-Injection.html" );
	script_tag( name: "summary", value: "This host is installed with PHP-Fusion and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able
  execute sql query or not." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web script
  or HTML in a user's browser session in the context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code or disclose or manipulation of arbitrary data." );
	script_tag( name: "affected", value: "PHP-Fusion Version 7.02.05 and prior versions may also be affected" );
	script_tag( name: "solution", value: "Upgrade to PHP-Fusion Version 7.02.06 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
url = dir + "/downloads.php?cat_id=1&orderby='SQL-Injection-Test";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "You have an error in your SQL syntax.*SQL-Injection-Test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

