CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804721" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-4238", "CVE-2014-4240", "CVE-2014-4233", "CVE-2014-2484", "CVE-2014-4214" );
	script_bugtraq_id( 68587, 68602, 68598, 68560, 68607 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-07-24 16:59:38 +0530 (Thu, 24 Jul 2014)" );
	script_name( "Oracle MySQL Multiple Unspecified vulnerabilities-01 July14 (Windows)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is prone to multiple unspecified
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL Server component via unknown vectors related
to SROPTZR, SRREP, SRFTS, and SRSP." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to manipulate certain data
and cause a DoS (Denial of Service)." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.6.17 and earlier on Windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59521" );
	script_xref( name: "URL", value: "http://www.computerworld.com/s/article/9249690/Oracle_to_release_115_security_patches" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixMSQL" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( mysqlVer, "^(5\\.6)" )){
	if(version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.17" )){
		report = report_fixed_ver( installed_version: mysqlVer, vulnerable_range: "5.6 - 5.6.17" );
		security_message( port: sqlPort, data: report );
		exit( 0 );
	}
}

