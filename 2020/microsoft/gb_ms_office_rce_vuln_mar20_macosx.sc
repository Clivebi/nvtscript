if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815582" );
	script_version( "2021-08-11T12:01:46+0000" );
	script_cve_id( "CVE-2020-0850", "CVE-2020-0851", "CVE-2020-0855", "CVE-2020-0892", "CVE-2020-0852" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-16 19:08:00 +0000 (Mon, 16 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 12:26:06 +0530 (Wed, 11 Mar 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities Mar20 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update for Microsoft Office 2016 and Office 2019 on Mac OSX according to
  Microsoft security update March 2020" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Flaws are due to Microsoft Excel and Word
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016 and Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 16.16.20 for Microsoft
  Office 2016 and to version 16.35 for Office 2019. Please see the references
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!offVer = get_kb_item( "MS/Office/MacOSX/Ver" )){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^1[56]\\." )){
	if( version_is_less( version: offVer, test_version: "16.16.20" ) ){
		fix = "16.16.20";
	}
	else {
		if(version_in_range( version: offVer, test_version: "16.17.0", test_version2: "16.34" )){
			fix = "16.35";
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: offVer, fixed_version: fix );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

