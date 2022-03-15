CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809709" );
	script_version( "$Revision: 12455 $" );
	script_cve_id( "CVE-2016-1950" );
	script_bugtraq_id( 84223 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-10-21 14:53:33 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Oracle GlassFish Server Unspecified Vulnerability-01 Oct16" );
	script_tag( name: "summary", value: "This host is running Oracle GlassFish Server
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error in
  'Security' sub-component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity and availability via unknown
  vectors." );
	script_tag( name: "affected", value: "Oracle GlassFish Server version 2.1.1" );
	script_tag( name: "solution", value: "Apply the patches from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!serPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!serVer = get_app_version( cpe: CPE, port: serPort )){
	exit( 0 );
}
if(version_is_equal( version: serVer, test_version: "2.1.1" )){
	report = report_fixed_ver( installed_version: serVer, fixed_version: "Apply the appropriate patch" );
	security_message( data: report, port: serPort );
	exit( 0 );
}
exit( 99 );

