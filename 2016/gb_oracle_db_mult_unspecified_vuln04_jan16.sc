CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807038" );
	script_version( "$Revision: 12088 $" );
	script_cve_id( "CVE-2014-4245", "CVE-2014-2478", "CVE-2015-0371", "CVE-2015-0370", "CVE-2014-6578", "CVE-2014-6514", "CVE-2014-6544", "CVE-2014-4289" );
	script_bugtraq_id( 68617, 70547, 72163, 72171, 72149, 72166, 70541 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 12:57:43 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)" );
	script_name( "Oracle Database Server Multiple Unspecified Vulnerabilities -04 Jan16" );
	script_tag( name: "summary", value: "This host is running  Oracle Database Server
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - multiple unspecified vulnerabilities in RDBMS Core component.

  - an unspecified vulnerability in the Workspace Manager component.

  - an unspecified vulnerability in PL/SQL component.

  - an unspecified vulnerability in the JDBC component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server versions
  11.1.0.7, 11.2.0.3, 11.2.0.4, and 12.1.0.1" );
	script_tag( name: "solution", value: "Apply the patche from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dbPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dbVer = get_app_version( cpe: CPE, port: dbPort )){
	exit( 0 );
}
if(IsMatchRegexp( dbVer, "^(12|11)" )){
	if(version_is_equal( version: dbVer, test_version: "11.2.0.4" ) || version_is_equal( version: dbVer, test_version: "11.2.0.3" ) || version_is_equal( version: dbVer, test_version: "11.1.0.7" ) || version_is_equal( version: dbVer, test_version: "12.1.0.1" )){
		report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
		security_message( data: report, port: dbPort );
		exit( 0 );
	}
}

