CPE = "cpe:/a:adobe:illustrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813673" );
	script_version( "2019-07-05T09:29:25+0000" );
	script_cve_id( "CVE-2014-0513" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-07-12 14:32:37 +0530 (Thu, 12 Jul 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Illustrator Remote Code Execution Vulnerability-Windows (apsb14-11)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Illustrator
  and is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error in the Adobe Illustrator." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "Adobe Illustrator CS6 before 16.0.5 and
  16.2.x before 16.2.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Illustrator CS6 version
  16.0.5 or 16.2.2 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/illustrator/apsb14-11.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_illustrator_detect_win.sc" );
	script_mandatory_keys( "Adobe/Illustrator/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
adobeVer = infos["version"];
adobePath = infos["location"];
if(IsMatchRegexp( adobeVer, "^16\\." )){
	if( version_is_less( version: adobeVer, test_version: "16.0.5" ) ){
		fix = "16.0.5";
	}
	else {
		if(version_in_range( version: adobeVer, test_version: "16.2", test_version2: "16.2.1" )){
			fix = "16.2.2";
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: adobeVer, fixed_version: fix, install_path: adobePath );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

