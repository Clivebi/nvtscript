CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808152" );
	script_version( "2019-05-03T14:30:54+0000" );
	script_cve_id( "CVE-2013-5767", "CVE-2013-5786", "CVE-2013-5793" );
	script_bugtraq_id( 63113, 63107, 63116 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-05-03 14:30:54 +0000 (Fri, 03 May 2019)" );
	script_tag( name: "creation_date", value: "2016-06-07 12:01:54 +0530 (Tue, 07 Jun 2016)" );
	script_name( "Oracle MySQL Multiple Unspecified vulnerabilities-34 Jun-2016 (Linux)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch the referenced advisory." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL
  Server component via unknown vectors related to Optimizer and InnoDB." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.6.12 and
  earlier on Linux" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to disclose sensitive information, manipulate certain data,
  cause a DoS (Denial of Service) and bypass certain security restrictions." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55327" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(IsMatchRegexp( mysqlVer, "^(5\\.6)" )){
	if(version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.12" )){
		report = report_fixed_ver( installed_version: mysqlVer, fixed_version: "Apply the patch" );
		security_message( data: report, port: sqlPort );
		exit( 0 );
	}
}

