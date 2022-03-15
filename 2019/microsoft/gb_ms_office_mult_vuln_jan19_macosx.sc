if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814757" );
	script_version( "2021-09-06T12:01:32+0000" );
	script_cve_id( "CVE-2019-0561", "CVE-2019-0585" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "creation_date", value: "2019-02-14 12:56:05 +0530 (Thu, 14 Feb 2019)" );
	script_tag( name: "last_modification", value: "2021-09-06 12:01:32 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Vulnerabilities-January19 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office 2016/2019 on Mac OSX according to Microsoft security
  update January 2019" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in Microsoft Word software when it fails to properly handle objects
    in memory.

  - An error when Microsoft Word macro buttons are used improperly." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to potentially sensitive information and execute arbitrary code
  on affected system" );
	script_tag( name: "affected", value: "- Microsoft Office 2016 on Mac OS X

  - Microsoft Office 2019 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Microsoft Office 2016 version
  16.16.6 (Build 19011400) or Microsoft Office 2019 version 16.21.0 (Build
  190101500) or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac" );
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
if(IsMatchRegexp( offVer, "^1[5|6]\\.)" )){
	if( version_is_less( version: offVer, test_version: "16.16.6" ) ){
		fix = "16.16.6";
	}
	else {
		if(IsMatchRegexp( offVer, "^(16\\.1[7|8|9]\\.)" ) && version_is_less( version: offVer, test_version: "16.21.0" )){
			fix = "16.21.0";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: offVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

