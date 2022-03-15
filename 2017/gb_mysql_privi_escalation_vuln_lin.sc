CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811630" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2008-4098" );
	script_bugtraq_id( 29106 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-14 17:56:34 +0530 (Mon, 14 Aug 2017)" );
	script_name( "MySQL Privilege Escalation Vulnerability - Linux" );
	script_tag( name: "summary", value: "MySQL is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to table creation option
  allows the use of the MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY
  options." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow an authenticated user to use the DATA DIRECTORY and INDEX DIRECTORY
  options to possibly bypass privilege checks." );
	script_tag( name: "affected", value: "MySQL version before 5.0.67 on Linux" );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.0.67." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://bugs.mysql.com/bug.php?id=32167" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
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
if(version_is_less( version: mysqlVer, test_version: "5.0.67" )){
	report = report_fixed_ver( installed_version: mysqlVer, fixed_version: "5.0.67" );
	security_message( data: report, port: sqlPort );
	exit( 0 );
}

