CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813738" );
	script_version( "2021-10-04T08:02:33+0000" );
	script_cve_id( "CVE-2018-14773" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-04 08:02:33 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-29 16:21:00 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-08-03 11:33:16 +0530 (Fri, 03 Aug 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Drupal Core Multiple Security Vulnerabilities (SA-CORE-2018-005) Windows" );
	script_tag( name: "summary", value: "Drupal is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to multiple errors
  in 3rd party libraries 'Symfony', 'zend-diactoros' and 'zend-feed' which are
  used in drupal. In each case, vulnerability let users override the path in the
  request URL via the X-Original-URL or X-Rewrite-URL HTTP request header which
  can allow a user to access one URL but have application return a different one." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass security restrictions and emulate the headers to request
  arbitrary content." );
	script_tag( name: "affected", value: "Drupal core versions 8.x before 8.5.6." );
	script_tag( name: "solution", value: "Update to version 8.5.6 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.drupal.org/SA-CORE-2018-005" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers" );
	script_xref( name: "URL", value: "https://framework.zend.com/security/advisory/ZF2018-01" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed", "Host/runs_windows" );
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
if(version_in_range( version: vers, test_version: "8.0", test_version2: "8.5.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.5.6", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

