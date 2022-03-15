if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112347" );
	script_version( "2021-06-15T02:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:00:29 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-06 11:16:33 +0200 (Mon, 06 Aug 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-14593" );
	script_name( "OTRS < 4.0.31, 5.0.29, 6.0.10 Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker who is logged into OTRS as a user may escalate their privileges by accessing a specially crafted URL." );
	script_tag( name: "affected", value: "OTRS 6.0.x up to and including 6.0.9, OTRS 5.0.x up to and including 5.0.28, and OTRS 4.0.x up to and including 4.0.30." );
	script_tag( name: "solution", value: "OTRS 6.0.10, OTRS 5.0.29, OTRS 4.0.31." );
	script_xref( name: "URL", value: "https://community.otrs.com/security-advisory-2018-03-security-update-for-otrs-framework/" );
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
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.30" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.31" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.28" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.29" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.10" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

