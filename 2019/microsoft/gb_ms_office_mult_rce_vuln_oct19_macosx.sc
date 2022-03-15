if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815494" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-1327", "CVE-2019-1331" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-10-09 18:53:41 +0530 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Remote Code Execution Vulnerabilities Oct19 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update for Microsoft Office 2016 on Mac OSX according to
  Microsoft security update October 2019" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when the Excel software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016 and Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to latest version provided by vendor.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1327" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1331" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
	if(version_is_less_equal( version: offVer, test_version: "16.16.14" ) || version_in_range( version: offVer, test_version: "16.17.0", test_version2: "16.29.1" )){
		report = report_fixed_ver( installed_version: offVer, fixed_version: "Upgrade to latest version provided by vendor" );
		security_message( data: report );
	}
}

