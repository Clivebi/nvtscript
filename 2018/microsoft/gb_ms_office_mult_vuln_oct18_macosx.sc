if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814268" );
	script_version( "2021-06-23T11:00:26+0000" );
	script_cve_id( "CVE-2018-8427", "CVE-2018-8432" );
	script_bugtraq_id( 105453, 105458 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 11:00:26 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-02 10:58:11 +0530 (Fri, 02 Nov 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Vulnerabilities-October18 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office 2016 on Mac OSX according to Microsoft security
  update October 2018" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to an error in the
  way that Microsoft Graphics Components handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to execute arbitrary code and obtain
  information that could be useful for further exploitation." );
	script_tag( name: "affected", value: "- Microsoft Office 2016 on Mac OS X

  - Microsoft Office 2019 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Microsoft Office 2016 version
  16.16.3 (Build 18101500) or Microsoft Office 2019 16.18.0 (Build 18101400)
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if( version_is_less( version: offVer, test_version: "16.16.3" ) ){
		fix = "16.16.3";
	}
	else {
		if(IsMatchRegexp( offVer, "^(16\\.1[7|8]\\.)" ) && version_is_less( version: offVer, test_version: "16.18.0" )){
			fix = "16.18.0";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: offVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

