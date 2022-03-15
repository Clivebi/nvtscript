CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805124" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_cve_id( "CVE-2014-4942" );
	script_bugtraq_id( 68692 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-01-13 12:25:08 +0530 (Tue, 13 Jan 2015)" );
	script_name( "WordPress EasyCart Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  EasyCart and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read system info or not." );
	script_tag( name: "insight", value: "Flaw is due to improper handling of a
  direct request for the /inc/admin/phpinfo.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose detailed system information." );
	script_tag( name: "affected", value: "WordPress EasyCart version 2.0.1
  through 2.0.5" );
	script_tag( name: "solution", value: "Update to version 2.0.6 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://codevigilant.com/disclosure/wp-plugin-wp-easycart-information-disclosure" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-easycart" );
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
url = dir + "/wp-content/plugins/wp-easycart/inc/admin/phpinfo.php";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: ">phpinfo\\(\\)<", extra_check: make_list( ">System",
	 ">Configuration File" ) )){
	security_message( port: http_port );
	exit( 0 );
}

