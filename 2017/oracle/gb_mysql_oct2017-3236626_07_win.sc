CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811997" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_cve_id( "CVE-2017-10279" );
	script_bugtraq_id( 101316 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 17:59:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-10-18 13:00:22 +0530 (Wed, 18 Oct 2017)" );
	script_name( "Oracle Mysql Security Updates (oct2017-3236626) 07 - Windows" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  'Server: Optimizer' component." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to compromise on availability of the system." );
	script_tag( name: "affected", value: "Oracle MySQL version
  5.6.36 and earlier, 5.7.18 and earlier on Windows." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sqlPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!mysqlVer = get_app_version( cpe: CPE, port: sqlPort )){
	exit( 0 );
}
if(version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.36" ) || version_in_range( version: mysqlVer, test_version: "5.7", test_version2: "5.7.18" )){
	report = report_fixed_ver( installed_version: mysqlVer, fixed_version: "Apply the patch" );
	security_message( data: report, port: sqlPort );
	exit( 0 );
}

