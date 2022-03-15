CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100077" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-03-26 13:41:22 +0100 (Thu, 26 Mar 2009)" );
	script_cve_id( "CVE-2009-1151" );
	script_bugtraq_id( 34236, 34251 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpMyAdmin Code Injection and XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34236" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34251" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a remote PHP code-injection vulnerability and
  to a cross-site scripting vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary
  malicious PHP code in the context of the webserver process. This may facilitate a compromise of the
  application and the underlying system. Other attacks are also possible." );
	script_tag( name: "affected", value: "Versions prior to phpMyAdmin 2.11.9.5 and 3.1.3.1 are vulnerable." );
	script_tag( name: "solution", value: "Update to version 2.11.9.5 / 3.1.3.1 or later." );
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
if(version_in_range( version: vers, test_version: "2.11", test_version2: "2.11.9.4" ) || version_in_range( version: vers, test_version: "3.1", test_version2: "3.1.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.11.9.5 / 3.1.3.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

