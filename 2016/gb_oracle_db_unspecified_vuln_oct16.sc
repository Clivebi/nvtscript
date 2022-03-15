CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809459" );
	script_version( "$Revision: 12323 $" );
	script_cve_id( "CVE-2010-5312" );
	script_bugtraq_id( 71106 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 16:36:30 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-10-21 17:28:09 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Oracle Database Server Unspecified Vulnerability Oct16" );
	script_tag( name: "summary", value: "This host is running Oracle Database Server
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified
  error in the Application Express component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated attackers to affect availability and integrity via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database Server versions
  before 5.0.4.00.07" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
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
if(version_is_less( version: dbVer, test_version: "5.0.4.00.07" )){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
	security_message( data: report, port: dbPort );
	exit( 0 );
}
exit( 99 );

