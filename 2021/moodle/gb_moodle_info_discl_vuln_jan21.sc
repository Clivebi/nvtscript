CPE = "cpe:/a:moodle:moodle";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145280" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 06:27:50 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-01 14:55:00 +0000 (Mon, 01 Feb 2021)" );
	script_cve_id( "CVE-2021-20184" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Moodle 3.8.x < 3.8.7, 3.9.x < 3.9.4, 3.10.x < 3.10.1 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Insufficient capability checks in some grade related web services meant
  students were able to view other students' grades." );
	script_tag( name: "affected", value: "Moodle versions 3.8 to 3.8.6, 3.9 to 3.9.3 and 3.10." );
	script_tag( name: "solution", value: "Update to version 3.8.7, 3.9.4, 3.10.1 or later." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=417167" );
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
if(version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.8.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.9.0", test_version2: "3.9.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^3\\.10" ) && version_is_less( version: version, test_version: "3.10.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.10.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

