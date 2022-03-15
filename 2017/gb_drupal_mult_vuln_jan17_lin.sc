CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108101" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-6377", "CVE-2017-6379", "CVE-2017-6381" );
	script_bugtraq_id( 96919 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-03-17 11:54:37 +0100 (Fri, 17 Mar 2017)" );
	script_name( "Drupal Multiple Vulnerabilities Jan17 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-2017-001" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/96919" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Editor module incorrectly checks access to inline private files.

  - Some admin paths were not protected with a CSRF token.

  - A 3rd party development library including with Drupal 8 development
  dependencies is vulnerable to remote code execution." );
	script_tag( name: "impact", value: "An attacker can exploit these issues
  to bypass certain security restrictions, perform unauthorized actions,
  and execute arbitrary code. Failed exploit attempts may result in a
  denial of service condition." );
	script_tag( name: "affected", value: "Drupal core 8.x versions prior to 8.2.7" );
	script_tag( name: "solution", value: "Upgrade to version 8.2.7 or newer." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port, version_regex: "^[0-9]\\.[0-9]+" )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "8.0", test_version2: "8.2.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.2.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

