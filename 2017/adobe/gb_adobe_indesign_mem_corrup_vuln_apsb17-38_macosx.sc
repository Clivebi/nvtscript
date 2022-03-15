CPE = "cpe:/a:adobe:indesign_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812094" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-11302" );
	script_bugtraq_id( 101840 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-26 18:10:00 +0000 (Tue, 26 Dec 2017)" );
	script_tag( name: "creation_date", value: "2017-11-16 15:17:21 +0530 (Thu, 16 Nov 2017)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Adobe InDesign Memory Corruption Vulnerability - APSB17-38 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is running Adobe InDesign and is
  prone to a memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified memory
  corruption error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected applications." );
	script_tag( name: "affected", value: "Adobe InDesign 12.1.0 and earlier
  versions on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 13.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/indesign/apsb17-38.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_indesign_server_detect_macosx.sc" );
	script_mandatory_keys( "InDesign/Server/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
desVer = infos["version"];
desPath = infos["location"];
if(version_is_less_equal( version: desVer, test_version: "12.1.0" )){
	report = report_fixed_ver( installed_version: desVer, fixed_version: "13.0", install_path: desPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

