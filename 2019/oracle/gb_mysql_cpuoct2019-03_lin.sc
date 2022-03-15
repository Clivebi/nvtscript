CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143029" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-10-23 05:25:25 +0000 (Wed, 23 Oct 2019)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_cve_id( "CVE-2019-2974", "CVE-2019-2911" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server <= 5.6.45 / 5.7 <= 5.7.27 / 8.0 <= 8.0.17 Security Update (cpuoct2019) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Oracle MySQL Server is prone to multiple vulnerabilities.

  For further information refer to the official advisory via the referenced link." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.6.45 and prior, 5.7 through 5.7.27 and 8.0 through 8.0.17." );
	script_tag( name: "solution", value: "Update to version 5.6.46, 5.7.28, 8.0.18 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2019.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuoct2019" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: version, test_version: "5.6.45" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.46", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.7", test_version2: "5.7.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.28", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.18", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

