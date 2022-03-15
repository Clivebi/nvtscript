CPE = "cpe:/a:adobe:indesign_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813085" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-4927", "CVE-2018-4928" );
	script_bugtraq_id( 103716, 103714 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-22 13:45:00 +0000 (Fri, 22 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-04-12 15:22:31 +0530 (Thu, 12 Apr 2018)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Adobe InDesign Code Execution And Privilege Escalation Vulnerabilities - APSB18-11 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is running Adobe InDesign and is
  prone to code execution and privilege escalation vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to memory corruption
  error and untrusted search path errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected applications and also to escalate privileges." );
	script_tag( name: "affected", value: "Adobe InDesign CC versions 13.0 and earlier on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 13.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/indesign/apsb18-11.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version_is_less( version: desVer, test_version: "13.1" )){
	report = report_fixed_ver( installed_version: desVer, fixed_version: "13.1", install_path: desPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

