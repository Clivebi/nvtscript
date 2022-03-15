CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803808" );
	script_version( "$Revision: 11865 $" );
	script_cve_id( "CVE-2012-1690", "CVE-2012-1688", "CVE-2012-1703" );
	script_bugtraq_id( 53074, 53067, 53058 );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-06-04 13:12:18 +0530 (Tue, 04 Jun 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_name( "MySQL Server Components Multiple Unspecified Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48890" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixMSQL" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_require_ports( "Services/mysql", 3306 );
	script_mandatory_keys( "MySQL/installed", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote authenticated users to affect
  availability via unknown vectors." );
	script_tag( name: "affected", value: "MySQL version 5.1.x before 5.1.62 and 5.5.x before 5.5.22" );
	script_tag( name: "insight", value: "Multiple unspecified error in Server Optimizer and Server DML components." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "The host is running MySQL and is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sqlPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
mysqlVer = get_app_version( cpe: CPE, port: sqlPort );
if(mysqlVer && IsMatchRegexp( mysqlVer, "^(5\\.(1|5))" )){
	if(version_in_range( version: mysqlVer, test_version: "5.1", test_version2: "5.1.61" ) || version_in_range( version: mysqlVer, test_version: "5.5", test_version2: "5.5.21" )){
		security_message( sqlPort );
		exit( 0 );
	}
}

