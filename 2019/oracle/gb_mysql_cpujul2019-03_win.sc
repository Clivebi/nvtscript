CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142647" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-07-23 10:33:33 +0000 (Tue, 23 Jul 2019)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-2731" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Oracle MySQL Server 5.7 <= 5.7.23 Security Update (cpujul2019) - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.7 through 5.7.23." );
	script_tag( name: "solution", value: "Update to version 5.7.24 or later." );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2019.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpujul2019" );
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
if(version_in_range( version: version, test_version: "5.7", test_version2: "5.7.23" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.24", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

