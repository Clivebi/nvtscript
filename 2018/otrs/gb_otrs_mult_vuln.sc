if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112389" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-01 12:12:22 +0200 (Mon, 01 Oct 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-21 17:55:00 +0000 (Wed, 21 Nov 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-16586", "CVE-2018-16587" );
	script_name( "OTRS < 6.0.11, < 5.0.30, < 4.0.32 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "- An attacker could send a malicious email to an OTRS system. If
  a logged in user opens it, the email could cause the browser to load external image or CSS
  resources.

  - An attacker could send a malicious email to an OTRS system. If a user with admin permissions
  opens it, it causes deletions of arbitrary files that the OTRS web server user has write
  access to." );
	script_tag( name: "affected", value: "OTRS 6.0.x up to and including 6.0.10, OTRS 5.0.x up to and
  including 5.0.29, and OTRS 4.0.x up to and including 4.0.31." );
	script_tag( name: "solution", value: "Update to OTRS version 6.0.11, 5.0.30 or 4.0.32 respectively." );
	script_xref( name: "URL", value: "https://community.otrs.com/security-advisory-2018-04-security-update-for-otrs-framework/" );
	script_xref( name: "URL", value: "https://community.otrs.com/security-advisory-2018-05-security-update-for-otrs-framework/" );
	exit( 0 );
}
CPE = "cpe:/a:otrs:otrs";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.31" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.32" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.29" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.30" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.11" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

