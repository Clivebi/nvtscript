CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801572" );
	script_version( "2019-05-13T14:05:09+0000" );
	script_tag( name: "last_modification", value: "2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)" );
	script_tag( name: "creation_date", value: "2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)" );
	script_cve_id( "CVE-2010-3835", "CVE-2010-3839" );
	script_bugtraq_id( 43676 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "MySQL Denial of Service (infinite loop) Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42875" );
	script_xref( name: "URL", value: "http://bugs.mysql.com/bug.php?id=54568" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.5/en/news-5-5-6.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-51.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow users to cause a denial of service and
  to execute arbitrary code." );
	script_tag( name: "affected", value: "MySQL 5.1 before 5.1.51 and 5.5 before 5.5.6." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Performing a user-variable assignment in a logical expression that is
  calculated and stored in a temporary table for GROUP BY, then causing the
  expression value to be used after the table is created, which causes the
  expression to be re-evaluated instead of accessing its value from the table.

  - An error in multiple invocations of a (1) prepared statement or (2) stored
  procedure that creates a query with nested JOIN statements." );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.1.51 or 5.5.6." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running MySQL and is prone to denial of service
  vulnerabilities." );
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
if(!isnull( mysqlVer[1] )){
	if(version_in_range( version: mysqlVer[1], test_version: "5.1", test_version2: "5.1.50" ) || version_in_range( version: mysqlVer[1], test_version: "5.5", test_version2: "5.5.5" )){
		security_message( sqlPort );
	}
}

