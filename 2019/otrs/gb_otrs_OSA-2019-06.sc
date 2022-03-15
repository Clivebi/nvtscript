CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142469" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-29 05:24:43 +0000 (Wed, 29 May 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-22 13:51:00 +0000 (Wed, 22 May 2019)" );
	script_cve_id( "CVE-2019-10066" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS 6.0.x < 6.0.18, 7.0.x < 7.0.7 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "An attacker who is logged into OTRS as an agent with appropriate permissions
  may create a carefully crafted calendar appointment in order to cause execution of JavaScript in the context of
  OTRS." );
	script_tag( name: "affected", value: "OTRS 6.0.x and 7.0.x." );
	script_tag( name: "solution", value: "Update to version 6.0.18, 7.0.7 or later." );
	script_xref( name: "URL", value: "https://community.otrs.com/security-advisory-2019-06-security-update-for-otrs-framework/" );
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
path = infos["location"];
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.18", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.7", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

