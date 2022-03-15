CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811897" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-16634" );
	script_bugtraq_id( 101701 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-28 17:20:00 +0000 (Tue, 28 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-08 10:36:51 +0530 (Wed, 08 Nov 2017)" );
	script_name( "Joomla! Core Two-factor Authentication Bypass Vulnerability Nov17" );
	script_tag( name: "summary", value: "Joomla is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error related to
  2-factor-authentication method." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow
  remote attackers to bypass certain security restrictions and perform unauthorized
  actions, this may aid in launching further attacks." );
	script_tag( name: "affected", value: "Joomla core version 3.2.0 through 3.8.1" );
	script_tag( name: "solution", value: "Upgrade to Joomla version 3.8.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/713-20171102-core-2-factor-authentication-bypass.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!jPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!jVer = get_app_version( cpe: CPE, port: jPort )){
	exit( 0 );
}
if(IsMatchRegexp( jVer, "^(3\\.)" )){
	if(version_in_range( version: jVer, test_version: "3.2.0", test_version2: "3.8.1" )){
		report = report_fixed_ver( installed_version: jVer, fixed_version: "3.8.2" );
		security_message( data: report, port: jPort );
		exit( 0 );
	}
}
exit( 0 );

