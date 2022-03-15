if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112535" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-18 09:29:11 +0100 (Mon, 18 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-23 15:15:00 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-9752" );
	script_name( "OTRS 7.0.x <= 7.0.3, 6.0.x <= 6.0.15 and 5.0.x <= 5.0.33 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker who is logged into OTRS as an agent or a customer user may upload a
  carefully crafted resource in order to cause execution of JavaScript in the context of OTRS." );
	script_tag( name: "affected", value: "OTRS 7.0.x up to and including 7.0.3, OTRS 6.0.x up to and including 6.0.15 and OTRS 5.0.x up to and including 5.0.33." );
	script_tag( name: "solution", value: "Update to OTRS version 7.0.4, 6.0.16 or 5.0.34 respectively." );
	script_xref( name: "URL", value: "https://community.otrs.com/security-advisory-2019-01-security-update-for-otrs-framework/" );
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
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.33" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.34" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.16" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.4" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

