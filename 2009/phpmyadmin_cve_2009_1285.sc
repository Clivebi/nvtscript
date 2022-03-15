CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100144" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_bugtraq_id( 34526 );
	script_cve_id( "CVE-2009-1285" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpMyAdmin 'CVE-2009-1285' Configuration File PHP Code Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34526" );
	script_tag( name: "summary", value: "According to its version number, the remote version of phpMyAdmin is
  prone to a remote PHP code-injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary
  malicious PHP code in the context of the webserver process. This may facilitate a compromise of the
  application and the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "phpMyAdmin 3.x versions prior to 3.1.3.2 are vulnerable." );
	script_tag( name: "solution", value: "Vendor updates are available." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3", test_version2: "3.1.3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

