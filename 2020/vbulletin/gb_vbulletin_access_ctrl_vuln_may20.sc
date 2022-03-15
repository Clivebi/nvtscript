CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143872" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-11 02:36:36 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 21:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_cve_id( "CVE-2020-12720" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "vBulletin < 5.6.1 Security Patch Level 1 Vulnerability" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "summary", value: "vBulletin has incorrect access controls." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "vBulletin versions prior to 5.5.6 Patch Level 1, 5.6.0 Patch Level 1 and
  5.6.1 Patch Level 1." );
	script_tag( name: "solution", value: "Update to 5.5.6 Patch Level 1, 5.6.0 Patch Level 1, 5.6.1 Patch Level 1
  or later." );
	script_xref( name: "URL", value: "https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4440032-vbulletin-5-6-1-security-patch-level-1" );
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
if(version_is_less_equal( version: version, test_version: "5.5.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.6 Patch Level 1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "5.6.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.0 Patch Level 1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "5.6.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.1 Patch Level 1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

