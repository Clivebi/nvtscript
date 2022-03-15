CPE = "cpe:/a:moodle:moodle";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145281" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 06:42:37 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-01 14:22:00 +0000 (Mon, 01 Feb 2021)" );
	script_cve_id( "CVE-2021-20185", "CVE-2021-20186", "CVE-2021-20187" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Moodle < 3.5.16, 3.8.x < 3.8.7, 3.9.x < 3.9.4, 3.10.x < 3.10.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Client side denial of service (CVE-2021-20185)

  - Stored cross-site scripting via TeX notation filter (CVE-2021-20186)

  - Arbitrary PHP code execution by site admins via Shibboleth configuration (CVE-2021-20187)" );
	script_tag( name: "affected", value: "Moodle version 3.5.15 and prior, 3.8 to 3.8.6, 3.9 to 3.9.3 and 3.10." );
	script_tag( name: "solution", value: "Update to version 3.5.16, 3.8.7, 3.9.4, 3.10.1 or later." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=417168" );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=417170" );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=417171" );
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
if(version_is_less( version: version, test_version: "3.5.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.5.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
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

