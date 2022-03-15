CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801065" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-7247" );
	script_name( "MySQL Authenticated Access Restrictions Bypass Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow users to bypass intended access restrictions
  by calling CREATE TABLE with  DATA DIRECTORY or INDEX DIRECTORY argument referring to a subdirectory." );
	script_tag( name: "affected", value: "MySQL 5.0.x before 5.0.88, 5.1.x before 5.1.41, 6.0 before 6.0.9-alpha." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'sql/sql_table.cc', when the data home directory
  contains a symlink to a different filesystem." );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.0.88 or 5.1.41 or 6.0.9-alpha." );
	script_tag( name: "summary", value: "The host is running MySQL and is prone to Access Restrictions Bypass
  Vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://lists.mysql.com/commits/59711" );
	script_xref( name: "URL", value: "http://bugs.mysql.com/bug.php?id=39277" );
	script_xref( name: "URL", value: "http://marc.info/?l=oss-security&m=125908040022018&w=2" );
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
mysqlVer = eregmatch( pattern: "([0-9.a-z]+)", string: mysqlVer );
if(!mysqlVer[1]){
	exit( 0 );
}
if( version_in_range( version: mysqlVer[1], test_version: "5.0", test_version2: "5.0.87" ) || version_in_range( version: mysqlVer[1], test_version: "5.1", test_version2: "5.1.40" ) ){
	report = report_fixed_ver( installed_version: mysqlVer[1], fixed_version: "5.0.88/5.1.41" );
	security_message( port: sqlPort, data: report );
	exit( 0 );
}
else {
	if(IsMatchRegexp( mysqlVer[1], "^6\\." )){
		if(version_is_less( version: mysqlVer[1], test_version: "6.0.9a" )){
			report = report_fixed_ver( installed_version: mysqlVer[1], fixed_version: "6.0.9a" );
			security_message( port: sqlPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

