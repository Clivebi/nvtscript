CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103539" );
	script_bugtraq_id( 55057 );
	script_cve_id( "CVE-2012-4219" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 11301 $" );
	script_name( "phpMyAdmin 'show_config_errors.php' Full Path Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55057" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/index.php" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-10 13:24:56 +0200 (Mon, 10 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-17 11:08:07 +0200 (Fri, 17 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "phpMyAdmin is prone to an information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information that
may lead to further attacks." );
	script_tag( name: "affected", value: "phpMyAdmin versions 3.5.x before 3.5.2.1 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/show_config_errors.php";
if(http_vuln_check( port: port, url: url, pattern: "Call to undefined function.*/.*" + dir + "/show_config_errors.php" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

