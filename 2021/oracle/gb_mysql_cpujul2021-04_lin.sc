CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146360" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-22 08:01:06 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "8.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-26 17:32:00 +0000 (Mon, 26 Jul 2021)" );
	script_cve_id( "CVE-2021-2417", "CVE-2021-2429", "CVE-2021-2339", "CVE-2021-2352", "CVE-2021-2399", "CVE-2021-2370", "CVE-2021-2440", "CVE-2021-2354", "CVE-2021-2402", "CVE-2021-2357", "CVE-2021-2367", "CVE-2021-2383", "CVE-2021-2384", "CVE-2021-2387", "CVE-2021-2410", "CVE-2021-2418", "CVE-2021-2425", "CVE-2021-2426", "CVE-2021-2427", "CVE-2021-2437", "CVE-2021-2441", "CVE-2021-2422", "CVE-2021-2424", "CVE-2021-2374", "CVE-2021-2340" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 8.0 <= 8.0.25 Security Update (cpujul2021) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Oracle MySQL Server version 8.0 through 8.0.25." );
	script_tag( name: "solution", value: "Update to version 8.0.26 or later." );
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
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.25" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.26", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

