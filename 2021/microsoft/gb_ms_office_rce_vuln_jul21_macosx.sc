if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818163" );
	script_version( "2021-09-24T08:01:25+0000" );
	script_cve_id( "CVE-2021-34501" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-24 08:01:25 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-20 12:21:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-07-14 19:53:52 +0530 (Wed, 14 Jul 2021)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Remote Code Execution Vulnerability Jul21 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update for Microsoft Office on Mac OSX according to Microsoft security update
  July 2021." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper input validation
  in the Microsoft Excel." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "Microsoft Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to latest version for Microsoft
  Office 2019 16.51 (Build 21071101). Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!vers = get_kb_item( "MS/Office/MacOSX/Ver" )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^16\\." )){
	if(version_in_range( version: vers, test_version: "16.17.0", test_version2: "16.50" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "16.51 (Build 21071101)" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

