if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112394" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-10-22 10:05:23 +0200 (Mon, 22 Oct 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Drupal Core Multiple Security Vulnerabilities (SA-CORE-2018-006) - Linux" );
	script_tag( name: "summary", value: "Drupal is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Drupal is prone to the following vulnerabilities:

  - In some conditions, content moderation fails to check a
  users access to use certain transitions, leading to an access bypass.

  - The path module allows users with the 'administer paths' to create pretty URLs for content.
  In certain circumstances the user can enter a particular path that triggers an open redirect to a malicious url.

  - Drupal core and contributed modules frequently use a 'destination' query string parameter
  in URLs to redirect users to a new destination after completing an action on the current page.
  Under certain circumstances, malicious users can use this parameter to construct a URL that will
  trick users into being redirected to a 3rd party website, thereby exposing the users to potential
  social engineering attacks.

  - When sending email some variables were not being sanitized for shell arguments,
  which could lead to remote code execution.

  - The Contextual Links module doesn't sufficiently validate the requested contextual links.
  This vulnerability is mitigated by the fact that an attacker must have a role with the permission 'access contextual links'." );
	script_tag( name: "affected", value: "Drupal core versions 7.x before 7.60, 8.5.x before 8.5.8 and 8.6.x before 8.6.2." );
	script_tag( name: "solution", value: "Update to version 7.60, 8.5.8 or 8.6.2 respectively." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2018-006" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	exit( 0 );
}
CPE = "cpe:/a:drupal:drupal";
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
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.59" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.60", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "8.5.0", test_version2: "8.5.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.5.8", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "8.6.0", test_version2: "8.6.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.6.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

