CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143612" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-03-19 05:39:32 +0000 (Thu, 19 Mar 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_cve_id( "CVE-2020-9281" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal 8.x CKEditor XSS Vulnerability (SA-CORE-2020-001) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Drupal is prone to a cross-site scripting (XSS)
  vulnerability in a third-party library." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the
  target host." );
	script_tag( name: "insight", value: "The Drupal project uses the third-party library
  CKEditor, which has released a security improvement that is needed to protect some
  Drupal configurations.

  Vulnerabilities are possible if Drupal is configured to use the WYSIWYG CKEditor for
  your site's users. When multiple people can edit content, the vulnerability can be used
  to execute XSS attacks against other people, including site admins with more access." );
	script_tag( name: "affected", value: "Drupal 8.7.x and 8.8.x." );
	script_tag( name: "solution", value: "Update to version 8.7.12, 8.8.4 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2020-001" );
	script_xref( name: "URL", value: "https://ckeditor.com/blog/CKEditor-4.14-with-Paste-from-LibreOffice-released/#security-issues-fixed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "8.7.0", test_version2: "8.7.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.7.12", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.8.0", test_version2: "8.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.8.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

