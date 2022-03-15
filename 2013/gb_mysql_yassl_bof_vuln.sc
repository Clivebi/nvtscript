CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803462" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0553", "CVE-2013-1492" );
	script_bugtraq_id( 58594, 58595 );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-04-04 13:53:42 +0530 (Thu, 04 Apr 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "MySQL 'yaSSL' Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52445" );
	script_xref( name: "URL", value: "http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-68.html" );
	script_xref( name: "URL", value: "https://blogs.oracle.com/sunsecurity/entry/cve_2012_0553_buffer_overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_dependencies( "mysql_version.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a buffer
  overflow resulting in loss of availability." );
	script_tag( name: "affected", value: "MySQL version 5.1.x before 5.1.68 and 5.5.x before 5.5.30" );
	script_tag( name: "insight", value: "Flaw is due an improper validation of user supplied data before copying it
  into an insufficient sized buffer." );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.1.68 or 5.5.30 or later." );
	script_tag( name: "summary", value: "The host is running MySQL and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sqlPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
mysqlVer = get_app_version( cpe: CPE, port: sqlPort );
if(mysqlVer && IsMatchRegexp( mysqlVer, "^(5.1|5.5)" )){
	if(version_in_range( version: mysqlVer, test_version: "5.1", test_version2: "5.1.67" ) || version_in_range( version: mysqlVer, test_version: "5.5", test_version2: "5.5.29" )){
		security_message( sqlPort );
		exit( 0 );
	}
}

