CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117211" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-09 09:51:55 +0000 (Tue, 09 Feb 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2013-1531" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server <= 5.1.66 / 5.5 <= 5.5.28 Security Update (cpuapr2013) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.1.66 and prior and 5.5 through 5.5.28." );
	script_tag( name: "solution", value: "Update to version 5.1.67, 5.5.29 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuapr2013.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuapr2013" );
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
if( version_is_less_equal( version: version, test_version: "5.1.66" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.1.67", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
else {
	if(version_in_range( version: version, test_version: "5.5", test_version2: "5.5.28" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "5.5.29", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

