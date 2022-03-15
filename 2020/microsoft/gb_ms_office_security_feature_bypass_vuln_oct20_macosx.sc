if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817513" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-16933" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-21 16:27:00 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-14 14:41:55 +0530 (Wed, 14 Oct 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Security Feature Bypass Vulnerability Oct20 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update for Microsoft Office on Mac OSX according to Microsoft security update October 2020" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Flaws are due to Microsoft Word software when it fails
  to properly handle .LNK files" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2016 and Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 16.16.27 for Microsoft
  Office 2016 and to version 16.42 for Office 2019. Please see the references
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
	if( version_is_less( version: offVer, test_version: "16.16.27" ) ){
		fix = "16.16.27";
	}
	else {
		if(version_in_range( version: offVer, test_version: "16.17.0", test_version2: "16.42" )){
			fix = "16.42";
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: offVer, fixed_version: fix );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

