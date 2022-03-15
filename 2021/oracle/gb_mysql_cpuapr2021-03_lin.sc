CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145797" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 05:53:11 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-13 18:15:00 +0000 (Thu, 13 May 2021)" );
	script_cve_id( "CVE-2020-28196", "CVE-2021-2172", "CVE-2021-2298", "CVE-2021-2304", "CVE-2021-2196", "CVE-2021-2300", "CVE-2021-2305", "CVE-2021-2164", "CVE-2021-2170", "CVE-2021-2193", "CVE-2021-2203", "CVE-2021-2212", "CVE-2021-2278", "CVE-2021-2299", "CVE-2021-2230", "CVE-2021-2201", "CVE-2021-2208", "CVE-2021-2215", "CVE-2021-2217", "CVE-2021-2293", "CVE-2021-2301", "CVE-2021-2308", "CVE-2021-2232" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 8.0 <= 8.0.23 Security Update (cpuapr2021) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Oracle MySQL Server version 8.0 through 8.0.23." );
	script_tag( name: "solution", value: "Update to version 8.0.24 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuapr2021" );
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
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.24", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

