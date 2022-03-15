CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112153" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-11 11:51:38 +0100 (Mon, 11 Dec 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-29 16:09:00 +0000 (Mon, 29 Apr 2019)" );
	script_cve_id( "CVE-2017-16854" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS Remote Code Execution Vulnerability - Dec '17" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker who is logged into OTRS as a customer can use the ticket search form
to disclose internal article information of their customer tickets." );
	script_tag( name: "affected", value: "OTRS 6.0.x up to and including 6.0.1, OTRS 5.0.x up to and including 5.0.24,
OTRS 4.0.x up to and including 4.0.26 and OTRS 3.3.x up to and including 3.3.20." );
	script_tag( name: "solution", value: "Upgrade to OTRS 6.0.2, OTRS 5.0.25, OTRS 4.0.27 or later.
No fix is being provided for OTRS 3.3.x since it has reached the end of its lifecycle. Please consider upgrading to a newer version of OTRS." );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2017-08-security-update-otrs-framework/" );
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
if(version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "This version has reached the end of its lifecycle. Please consider upgrade to a newer OTRS version." );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.26" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.27" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.25" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

