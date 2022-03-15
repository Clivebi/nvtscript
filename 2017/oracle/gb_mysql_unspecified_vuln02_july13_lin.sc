CPE = "cpe:/a:mysql:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812185" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2013-3812", "CVE-2013-3809", "CVE-2013-3793" );
	script_bugtraq_id( 61249, 61272, 61264 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-22 15:34:35 +0530 (Wed, 22 Nov 2017)" );
	script_name( "MySQL Unspecified vulnerabilities-02 July-2013 (Linux)" );
	script_tag( name: "summary", value: "MySQL is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "insight", value: "Unspecified errors in the MySQL Server
  component via unknown vectors related to Server Replication, Audit Log and
  Data Manipulation Language." );
	script_tag( name: "affected", value: "Oracle MySQL 5.5.31 and earlier,
  5.6.11 and earlier on Linux" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote authenticated users to affect integrity and availability via unknown
  vectors and cause denial of service." );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "MySQL/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sqlPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: sqlPort, exit_no_version: TRUE )){
	exit( 0 );
}
mysqlVer = infos["version"];
mysqlPath = infos["location"];
if(mysqlVer && IsMatchRegexp( mysqlVer, "^(5\\.(5|6))" )){
	if(version_in_range( version: mysqlVer, test_version: "5.5", test_version2: "5.5.31" ) || version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.11" )){
		report = report_fixed_ver( installed_version: mysqlVer, fixed_version: "Apply the patch", install_path: mysqlPath );
		security_message( port: sqlPort, data: report );
		exit( 0 );
	}
}

