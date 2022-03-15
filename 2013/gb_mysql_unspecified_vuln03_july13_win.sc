CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803725" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_cve_id( "CVE-2013-3801", "CVE-2013-3805", "CVE-2013-3794" );
	script_bugtraq_id( 61269, 61256, 61222 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-07-29 17:28:24 +0530 (Mon, 29 Jul 2013)" );
	script_name( "MySQL Unspecified vulnerabilities-03 July-2013 (Windows)" );
	script_tag( name: "summary", value: "This host is running MySQL and is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL Server component via unknown vectors related
  to Prepared Statements, Server Options and Server Partition." );
	script_tag( name: "affected", value: "Oracle MySQL 5.5.30 and earlier and 5.6.10 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated users to affect
  availability via unknown vectors." );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
mysqlVer = get_app_version( cpe: CPE, port: sqlPort );
if(mysqlVer && IsMatchRegexp( mysqlVer, "^5\\.[56]" )){
	if(version_is_equal( version: mysqlVer, test_version: "5.6.10" ) || version_in_range( version: mysqlVer, test_version: "5.5", test_version2: "5.5.30" )){
		security_message( sqlPort );
		exit( 0 );
	}
}

