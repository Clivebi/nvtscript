if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815841" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-1457", "CVE-2019-1448", "CVE-2019-1446" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-13 09:00:35 +0530 (Wed, 13 Nov 2019)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Vulnerabilities Nov19 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update for Microsoft Office 2016 and Office 2019 on Mac OSX according to
  Microsoft security update November 2019" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Microsoft Excel improperly discloses the contents of its memory.

  - Microsoft Excel software fails to properly handle objects in memory.

  - Microsoft Office software not enforcing macro settings on an Excel document." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to bypass security restrictions, run arbitrary code in the context of the
  current user and disclose sensitive information." );
	script_tag( name: "affected", value: "Microsoft Office 2016 and Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 16.16.16 for Microsoft
  Office 2016 and to version 16.31 for Office 2019. Please see the references
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1457" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1446" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1448" );
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
	if( version_is_less( version: offVer, test_version: "16.16.16" ) ){
		fix = "16.16.16";
	}
	else {
		if(version_in_range( version: offVer, test_version: "16.17.0", test_version2: "16.30" )){
			fix = "16.31";
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: offVer, fixed_version: fix );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

