CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808705" );
	script_version( "$Revision: 12338 $" );
	script_cve_id( "CVE-2016-3608" );
	script_bugtraq_id( 92031 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-22 12:15:22 +0530 (Fri, 22 Jul 2016)" );
	script_name( "Oracle GlassFish Server Unspecified Vulnerability -01 July16" );
	script_tag( name: "summary", value: "This host is running Oracle GlassFish Server
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error in
  the Administration sub-component." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality via unknown vectors." );
	script_tag( name: "affected", value: "Oracle GlassFish Server version 3.0.1" );
	script_tag( name: "solution", value: "Apply the patches from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
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
if(version_is_equal( version: dbVer, test_version: "3.0.1" )){
	report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
	security_message( data: report, port: dbPort );
	exit( 0 );
}
exit( 99 );

