CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811437" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-3633", "CVE-2017-3634", "CVE-2017-3649", "CVE-2017-3647" );
	script_bugtraq_id( 99722, 99729, 99799, 99796 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-07-19 11:07:12 +0530 (Wed, 19 Jul 2017)" );
	script_name( "Oracle Mysql Security Updates (jul2017-3236622) 04 - Linux" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A flaw in the Server: Memcached component.

  - A flaw in the Server: DML component.

  - A flaw in the Server: Replication component." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote to partially modify data and cause denial of service conditions." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.6.36 and earlier,
  5.7.18 and earlier, on Linux" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixMSQL" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed", "Host/runs_unixoide" );
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
if(version_in_range( version: mysqlVer, test_version: "5.6.0", test_version2: "5.6.36" ) || version_in_range( version: mysqlVer, test_version: "5.7.0", test_version2: "5.7.18" )){
	report = report_fixed_ver( installed_version: mysqlVer, fixed_version: "Apply the patch" );
	security_message( data: report, port: sqlPort );
	exit( 0 );
}

