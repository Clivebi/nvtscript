CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810759" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-6919" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-20 12:14:26 +0530 (Thu, 20 Apr 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal Core Access Bypass Vulnerability (SA-CORE-2017-002)" );
	script_tag( name: "summary", value: "Drupal is prone to an access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal has released an advisory to address
  access bypass vulnerability in Drupal core.

  A site is only affected by this if all of the following conditions are met:

  The site has the RESTful Web Services (rest) module enabled.
  The site allows PATCH requests.
  An attacker can get or register a user account on the site." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information." );
	script_tag( name: "affected", value: "Drupal version 8 prior to 8.2.8 and 8.3.1" );
	script_tag( name: "solution", value: "Upgrade to version 8.2.8, 8.3.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2017-002" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc" );
	script_mandatory_keys( "drupal/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!drupalPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!drupalVer = get_app_version( cpe: CPE, port: drupalPort, version_regex: "^[0-9]\\.[0-9]+" )){
	exit( 0 );
}
if( IsMatchRegexp( drupalVer, "^(8\\.)" ) ){
	if(version_in_range( version: drupalVer, test_version: "8.0", test_version2: "8.2.7" )){
		VULN = TRUE;
		fix = "8.2.8";
	}
}
else {
	if(version_is_equal( version: drupalVer, test_version: "8.3.0" )){
		VULN = TRUE;
		fix = "8.3.1";
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: drupalVer, fixed_version: fix );
	security_message( data: report, port: drupalPort );
	exit( 0 );
}

