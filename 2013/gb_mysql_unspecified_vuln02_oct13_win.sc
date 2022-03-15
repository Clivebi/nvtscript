CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804033" );
	script_version( "$Revision: 11878 $" );
	script_cve_id( "CVE-2013-3839" );
	script_bugtraq_id( 63109 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-10-28 16:26:24 +0530 (Mon, 28 Oct 2013)" );
	script_name( "Oracle MySQL Server Component 'Optimizer' Unspecified vulnerability Oct-2013 (Windows)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "insight", value: "Unspecified error in the MySQL Server component via unknown vectors related
to Optimizer." );
	script_tag( name: "affected", value: "Oracle MySQL versions 5.1.51 through 5.1.70, 5.5.10 through 5.5.32, and 5.6.x
through 5.6.12 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to disclose sensitive
information, manipulate certain data, cause a DoS (Denial of Service) and
bypass certain security restrictions." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55327" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
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
if(!mysqlVer = get_app_version( cpe: CPE, port: sqlPort )){
	exit( 0 );
}
if(IsMatchRegexp( mysqlVer, "^(5\\.(1|5|6))" )){
	if(version_in_range( version: mysqlVer, test_version: "5.1.51", test_version2: "5.1.70" ) || version_in_range( version: mysqlVer, test_version: "5.5.10", test_version2: "5.5.32" ) || version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.12" )){
		security_message( sqlPort );
		exit( 0 );
	}
}

