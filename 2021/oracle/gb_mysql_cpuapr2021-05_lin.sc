CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145801" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 06:23:17 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_cve_id( "CVE-2021-2154" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server <= 5.7.33 Security Update (cpuapr2021) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Oracle MySQL Server version 5.7.33 and prior." );
	script_tag( name: "solution", value: "Update to version 5.7.34 or later." );
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
if(version_is_less_equal( version: version, test_version: "5.7.33" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.34", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

