CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811830" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2015-2750", "CVE-2015-2749", "CVE-2015-2559" );
	script_bugtraq_id( 73219, 73403, 73219 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-20 19:15:00 +0000 (Wed, 20 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-09-19 14:05:10 +0530 (Tue, 19 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Core Multiple Vulnerabilities (SA-CORE-2015-001) - Windows" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper validation for 'destination' query string parameter in URLs to
    redirect users to a new destination after completing an action on the current
    page.

  - An improper implementation of several URL-related API functions.

  - An improper handling of Password reset URLs." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to another user's account without knowing the
  account's password and also trick users into being redirected to a 3rd party
  website, thereby exposing the users to potential social engineering attacks." );
	script_tag( name: "affected", value: "Drupal core 6.x versions prior to 6.35 and
  7.x versions prior to 7.35 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Drupal core version 6.35 or
  7.35 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2015-001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!drupalPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!drupalVer = get_app_version( cpe: CPE, port: drupalPort, version_regex: "^[0-9]\\.[0-9.]+" )){
	exit( 0 );
}
if( IsMatchRegexp( drupalVer, "^(6\\.)" ) && version_is_less( version: drupalVer, test_version: "6.35" ) ){
	fix = "6.35";
}
else {
	if(IsMatchRegexp( drupalVer, "^(7\\.)" ) && version_is_less( version: drupalVer, test_version: "7.35" )){
		fix = "7.35";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: drupalVer, fixed_version: fix );
	security_message( data: report, port: drupalPort );
	exit( 0 );
}

