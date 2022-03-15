CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146355" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-22 07:49:30 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-26 16:30:00 +0000 (Mon, 26 Jul 2021)" );
	script_cve_id( "CVE-2021-22901", "CVE-2019-17543", "CVE-2021-2389", "CVE-2021-2390", "CVE-2021-2356", "CVE-2021-2385", "CVE-2021-2342", "CVE-2021-2372", "CVE-2021-22897", "CVE-2021-22898" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server <= 5.7.34 / 8.0 <= 8.0.25 Security Update (cpujul2021) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Oracle MySQL Server version 5.7.34 and prior and 8.0 through 8.0.25." );
	script_tag( name: "solution", value: "Update to version 5.7.35, 8.0.26 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2021.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpujul2021" );
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
location = infos["location"];
if( version_is_less_equal( version: version, test_version: "5.7.34" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.35", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.25" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.0.26", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

