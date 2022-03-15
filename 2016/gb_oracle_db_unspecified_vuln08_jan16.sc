CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807048" );
	script_version( "$Revision: 12110 $" );
	script_cve_id( "CVE-2015-0468" );
	script_bugtraq_id( 75853 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:58:59 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)" );
	script_name( "Oracle Database Server Unspecified Vulnerability -08 Jan16" );
	script_tag( name: "summary", value: "This host is running  Oracle Database Server
  and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified
  error in the Core RDBMS component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability via unknown
  vectors." );
	script_tag( name: "affected", value: "Oracle Database Server versions
  11.1.0.7, 11.2.0.3, and 12.1.0.1" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html" );
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
if(IsMatchRegexp( dbVer, "^(11|12)" )){
	if(version_is_equal( version: dbVer, test_version: "12.1.0.1" ) || version_is_equal( version: dbVer, test_version: "11.2.0.3" ) || version_is_equal( version: dbVer, test_version: "11.1.0.7" )){
		report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
		security_message( data: report, port: dbPort );
		exit( 0 );
	}
}

