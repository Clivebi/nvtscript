CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808704" );
	script_version( "$Revision: 11837 $" );
	script_cve_id( "CVE-2016-3607", "CVE-2015-3237", "CVE-2017-3239", "CVE-2017-10391", "CVE-2017-10385", "CVE-2017-10393" );
	script_bugtraq_id( 75387, 95493, 101364, 101360, 101347 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-11 11:17:05 +0200 (Thu, 11 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-07-22 11:55:11 +0530 (Fri, 22 Jul 2016)" );
	script_name( "Oracle GlassFish Server Multiple Unspecified Vulnerabilities -01 July16" );
	script_tag( name: "summary", value: "This host is running Oracle GlassFish Server
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple
  unspecified errors in the Web Container and Administration
  sub-components." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors." );
	script_tag( name: "affected", value: "Oracle GlassFish Server versions 3.0.1,
  and 3.1.2" );
	script_tag( name: "solution", value: "Apply patches." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
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
if(IsMatchRegexp( dbVer, "^(3\\.)" )){
	if(version_is_equal( version: dbVer, test_version: "3.0.1" ) || version_is_equal( version: dbVer, test_version: "3.1.2" )){
		report = report_fixed_ver( installed_version: dbVer, fixed_version: "Apply the appropriate patch" );
		security_message( data: report, port: dbPort );
		exit( 0 );
	}
}
exit( 99 );

