CPE = "cpe:/a:oracle:mysql";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808126" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-4756" );
	script_bugtraq_id( 75785 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-06-03 13:42:29 +0530 (Fri, 03 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle MySQL Unspecified Vulnerability-14 Jun16 (Linux)" );
	script_tag( name: "summary", value: "This host is running Oracle MySQL and is
  prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified error exists in the MySQL Server
  component via unknown vectors related to Server : InnoDB." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  authenticated remote attacker to cause denial of service attack." );
	script_tag( name: "affected", value: "Oracle MySQL Server 5.6.22 and earlier on Linux." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
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
	if(version_in_range( version: mysqlVer, test_version: "5.6", test_version2: "5.6.22" )){
		report = "Installed version: " + mysqlVer + "\n";
		security_message( data: report, port: sqlPort );
		exit( 0 );
	}
}

