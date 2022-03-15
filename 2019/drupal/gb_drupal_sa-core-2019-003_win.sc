CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142012" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-21 08:51:57 +0700 (Thu, 21 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-6340" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal RCE Vulnerability (SA-CORE-2019-003) (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Some field types do not properly sanitize data from non-form sources. This
can lead to arbitrary PHP code execution in some cases." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A site is only affected by this if one of the following conditions is met:

  - The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests,
    or

  - the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web
    Services in Drupal 7." );
	script_tag( name: "affected", value: "Drupal 8.5.x and 8.6.x." );
	script_tag( name: "solution", value: "Update to version 8.5.11, 8.6.10 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-003" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.5.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.6", test_version2: "8.6.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.6.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

