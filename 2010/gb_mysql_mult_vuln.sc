CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801355" );
	script_version( "2019-05-13T14:05:09+0000" );
	script_tag( name: "last_modification", value: "2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)" );
	script_tag( name: "creation_date", value: "2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)" );
	script_cve_id( "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "MySQL Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/May/1024031.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/May/1024033.html" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/May/1024032.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/refman/5.0/en/news-5-0-91.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow users to cause a denial of service and
  to execute arbitrary code." );
	script_tag( name: "affected", value: "MySQL 5.0.x before 5.0.91 and 5.1.x before 5.1.47 on all running platform." );
	script_tag( name: "insight", value: "The flaws are due to:

  - An error in 'my_net_skip_rest()' function in 'sql/net_serv.cc' when handling
  a large number of packets that exceed the maximum length, which allows remote
  attackers to cause a denial of service (CPU and bandwidth consumption).

  - buffer overflow when handling 'COM_FIELD_LIST' command with a long
  table name, allows remote authenticated users to execute arbitrary code.

  - directory traversal vulnerability when handling a '..' (dot dot) in a
  table name, which allows remote authenticated users to bypass intended
  table grants to read field definitions of arbitrary tables." );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.0.91 or 5.1.47." );
	script_tag( name: "summary", value: "The host is running MySQL and is prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
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
	if(version_in_range( version: mysqlVer[1], test_version: "5.0", test_version2: "5.0.90" ) || version_in_range( version: mysqlVer[1], test_version: "5.1", test_version2: "5.1.46" )){
		security_message( sqlPort );
	}
}

