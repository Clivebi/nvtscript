CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805768" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-4910", "CVE-2015-4890", "CVE-2015-4862", "CVE-2015-4800", "CVE-2015-4791" );
	script_bugtraq_id( 77234, 77231, 77216, 77213, 77147 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-28 13:07:06 +0530 (Wed, 28 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Oracle MySQL Multiple Unspecified Vulnerabilities-05 Oct15 (Windows)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified errors exist in the MySQL Server
  component via unknown vectors related to Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle MySQL Server 5.6.26 and earlier
  on windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
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
	if(version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.26" )){
		report = "Installed version: " + mysqlVer + "\n" + "Fixed version:     " + "Apply the patch" + "\n";
		security_message( data: report, port: sqlPort );
		exit( 0 );
	}
}

