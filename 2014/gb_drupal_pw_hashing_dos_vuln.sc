CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105934" );
	script_version( "$Revision: 14033 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-09 16:56:24 +0700 (Tue, 09 Dec 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2014-9016" );
	script_bugtraq_id( 71202 );
	script_name( "Drupal Password Hashing Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "drupal/installed" );
	script_tag( name: "summary", value: "A vulnerability in the password hashing API of Drupal 7 can lead
  to a DoS." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal 7 includes a password hashing API to ensure that user
  supplied passwords are not stored in plain text. An attacker can send specially crafted requests
  resulting in CPU and memory exhaustion." );
	script_tag( name: "impact", value: "An unauthenticated attacker can cause a denial of service." );
	script_tag( name: "affected", value: "Drupal 7 before 7.34." );
	script_tag( name: "solution", value: "Upgrade to Drupal 7.34 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2014-006" );
	script_xref( name: "URL", value: "http://www.behindthefirewalls.com/2014/12/cve-2014-9016-and-cve-2014-9034-PoC.html" );
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
if(IsMatchRegexp( version, "^7" )){
	if(version_is_less( version: version, test_version: "7.34" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.34" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

