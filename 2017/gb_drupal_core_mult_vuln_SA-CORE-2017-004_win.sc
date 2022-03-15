CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811704" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-6923", "CVE-2017-6924", "CVE-2017-6925" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-17 10:00:18 +0530 (Thu, 17 Aug 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Core Multiple Vulnerabilities (SA-CORE-2017-004) - Windows" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the 'views' subsystem/module which did not restrict access to
    the Ajax endpoint to only views configured to use Ajax.

  - An error when using the REST API, users without the correct permission can
    post comments via REST that are approved even if the user does not have
    permission to post approved comments.

  - An error in the entity access system that could allow unwanted access to
    view, create, update, or delete entities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions." );
	script_tag( name: "affected", value: "Drupal core version 8.x versions prior to
  8.3.7 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Drupal core version 8.3.7 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2017-004" );
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
if(IsMatchRegexp( drupalVer, "^(8\\.)" ) && version_is_less( version: drupalVer, test_version: "8.3.7" )){
	report = report_fixed_ver( installed_version: drupalVer, fixed_version: "8.3.7" );
	security_message( data: report, port: drupalPort );
	exit( 0 );
}

