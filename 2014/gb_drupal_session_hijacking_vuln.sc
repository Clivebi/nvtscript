CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105935" );
	script_version( "$Revision: 14033 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-09 16:55:49 +0700 (Tue, 09 Dec 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2014-9015" );
	script_bugtraq_id( 71195 );
	script_name( "Drupal Session Hijacking Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "drupal/installed" );
	script_tag( name: "summary", value: "Drupal is vulnerable to session hijacking." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A special crafted request can give a user access to another
  user's session, allowing an attacker to hijack a random session." );
	script_tag( name: "impact", value: "An attacker may gain unauthorized access to the application." );
	script_tag( name: "affected", value: "Drupal 6.x versions prior to 6.34. Drupal 7.x versions prior to 7.34." );
	script_tag( name: "solution", value: "Upgrade to Drupal 6.34, 7.34 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2014-006" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port, version_regex: "^[0-9]\\.[0-9]+" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.34" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.34" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7" )){
	if(version_is_less( version: version, test_version: "7.34" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.34" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

