if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814756" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-0669" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "creation_date", value: "2019-02-14 12:56:05 +0530 (Thu, 14 Feb 2019)" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Vulnerabilities-February19 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office 2016/2019 on Mac OSX according to Microsoft security
  update February 2019" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error when Microsoft
  Excel improperly discloses the contents of its memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to potentially sensitive information and use the information to
  compromise the user's computer or data." );
	script_tag( name: "affected", value: "- Microsoft Office 2016 on Mac OS X

  - Microsoft Office 2019 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Microsoft Office 2016 version
  16.16.7 (Build 19021001) or Microsoft Office 2019 version 16.22.0 (Build
  19021100) or later. Please see the references for more information." );
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
	if( version_is_less( version: offVer, test_version: "16.16.7" ) ){
		fix = "16.16.7";
	}
	else {
		if(IsMatchRegexp( offVer, "^(16\\.1[7|8|9]\\.)" ) && version_is_less( version: offVer, test_version: "16.22.0" )){
			fix = "16.22.0";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: offVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

