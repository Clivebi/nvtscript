CPE = "cpe:/a:phpmyfaq:phpmyfaq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100372" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-12-02 19:43:26 +0100 (Wed, 02 Dec 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4780" );
	script_bugtraq_id( 37180 );
	script_name( "phpMyFAQ 2.5.4 and Prior Multiple Unspecified Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37180" );
	script_xref( name: "URL", value: "http://www.phpmyfaq.de/" );
	script_xref( name: "URL", value: "http://www.phpmyfaq.de/advisory_2009-12-01.php" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phpmyfaq_detect.sc" );
	script_mandatory_keys( "phpmyfaq/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "phpMyFAQ is prone to multiple cross-site scripting vulnerabilities because
  the application fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in
  the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials
  and to launch other attacks." );
	script_tag( name: "affected", value: "Versions prior to phpMyFAQ 2.5.5 are vulnerable." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.5.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See Advisory" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
