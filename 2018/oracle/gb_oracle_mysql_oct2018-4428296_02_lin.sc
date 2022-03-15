CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814259" );
	script_version( "2021-09-07T07:55:26+0000" );
	script_cve_id( "CVE-2018-3133", "CVE-2018-3174", "CVE-2018-3282", "CVE-2016-9843", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 07:55:26 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 21:15:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-10-17 11:11:46 +0530 (Wed, 17 Oct 2018)" );
	script_name( "Oracle Mysql Security Update (cpuoct2018 - 02) - Linux" );
	script_tag( name: "summary", value: "Oracle MySQL is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An unspecified error within 'InnoDB (zlib)' component of MySQL Server.

  - An unspecified error within 'Server: Parser' component of MySQL Server.

  - An unspecified error within 'Client programs' component of MySQL Server.

  - An unspecified error within 'Server: Storage Engines' component of MySQL Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.5.x through 5.5.61,
  5.6.x through 5.6.41, 5.7.x through 5.7.23 and 8.0.x through 8.0.12." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
  more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuoct2018.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpuoct2018" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "MySQL/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.61" ) || version_in_range( version: vers, test_version: "5.6", test_version2: "5.6.41" ) || version_in_range( version: vers, test_version: "5.7", test_version2: "5.7.23" ) || version_in_range( version: vers, test_version: "8.0", test_version2: "8.0.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See reference", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

