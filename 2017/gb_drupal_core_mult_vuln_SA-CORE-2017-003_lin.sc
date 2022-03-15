CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810959" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-6920", "CVE-2017-6921", "CVE-2017-6922" );
	script_bugtraq_id( 99211, 99222, 99219 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-04 16:16:00 +0000 (Thu, 04 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-06-22 14:36:14 +0530 (Thu, 22 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal Core Multiple Vulnerabilities (SA-CORE-2017-003) - Linux" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - PECL YAML parser does not handle PHP objects safely during certain
    operations within Drupal core.

  - The file REST resource does not properly validate some fields when
    manipulating files.

  - Private files that have been uploaded by an anonymous user but not
    permanently attached to content on the site is visible to the anonymous
    user, Drupal core did not provide sufficient protection." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code, get or register a user account on the
  site with permissions to upload files into a private file system and
  modify the file resource." );
	script_tag( name: "affected", value: "Drupal core version 7.x versions prior to
  7.56 and 8.x versions prior to 8.3.4." );
	script_tag( name: "solution", value: "Upgrade to Drupal core version 7.56 or
  8.3.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2017-003" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
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
if( IsMatchRegexp( drupalVer, "^(8\\.)" ) ){
	if(version_is_less( version: drupalVer, test_version: "8.3.4" )){
		fix = "8.3.4";
	}
}
else {
	if(IsMatchRegexp( drupalVer, "^(7\\.)" )){
		if(version_is_less( version: drupalVer, test_version: "7.56" )){
			fix = "7.56";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: drupalVer, fixed_version: fix );
	security_message( data: report, port: drupalPort );
	exit( 0 );
}

