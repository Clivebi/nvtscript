CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802430" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_bugtraq_id( 52858 );
	script_cve_id( "CVE-2012-1902" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-04-17 12:56:58 +0530 (Tue, 17 Apr 2012)" );
	script_name( "phpMyAdmin 'show_config_errors.php' Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://english.securitylab.ru/nvd/422861.php" );
	script_xref( name: "URL", value: "http://www.auscert.org.au/render.html?it=15653" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=809146" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2012-2.php" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "phpMyAdmin Version 3.4.10.2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an input validation error in
  'show_config_errors.php'. When a configuration file does not exist, allows
  remote attackers to obtain sensitive information via a direct request." );
	script_tag( name: "solution", value: "Upgrade to phpMyAdmin 3.4.10.2 later." );
	script_tag( name: "summary", value: "This host is running phpMyAdmin and is prone to information
  disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(dir = get_app_location( cpe: CPE, port: port )){
	url = dir + "/show_config_errors.php";
	if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "Failed opening required.*\\show_config_errors.php" )){
		security_message( port: port );
	}
}
exit( 0 );

