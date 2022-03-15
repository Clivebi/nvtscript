CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812776" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2017-6926", "CVE-2017-6927", "CVE-2017-6928", "CVE-2017-6929", "CVE-2017-6930", "CVE-2017-6931", "CVE-2017-6932" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-02-22 10:43:18 +0530 (Thu, 22 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal Core Multiple Vulnerabilities (SA-CORE-2018-001) - Linux" );
	script_tag( name: "summary", value: "Drupal is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An improper access restriction for sensitive contents via 'Comment reply form'.

  - 'Drupal.checkPlain' JavaScript function does not correctly handle all methods
    of injecting malicious HTML.

  - Private file access check fails under certain conditions in which one module
    is trying to grant access to the file and another is trying to deny it.

  - A jQuery cross site scripting vulnerability is present when making Ajax
    requests to untrusted domains.

  - Language fallback can be incorrect on multilingual sites with node access
    restrictions.

  - An error in 'Settings Tray module'.

  - An external link injection vulnerability when the language switcher block
    is used." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to trick users into unwillingly navigating to an external site,
  update certain data that they do not have the permissions for, execute
  arbitrary script and gain extra privileges." );
	script_tag( name: "affected", value: "Drupal core version 8.x versions prior to
  8.4.5 and 7.x versions prior to 7.57." );
	script_tag( name: "solution", value: "Update to version 8.4.5 or
  7.57 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2018-001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, version_regex: "^[0-9]\\.[0-9]+", exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^8\\." ) && version_is_less( version: vers, test_version: "8.4.5" )){
	fix = "8.4.5";
}
if(IsMatchRegexp( vers, "^7\\." ) && version_is_less( version: vers, test_version: "7.57" )){
	fix = "7.57";
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

