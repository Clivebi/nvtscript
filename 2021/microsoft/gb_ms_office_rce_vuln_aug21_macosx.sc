if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817747" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_cve_id( "CVE-2021-36941" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-20 19:00:00 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 14:02:15 +0530 (Wed, 11 Aug 2021)" );
	script_name( "Microsoft Office 2019 Remote Code Execution Vulnerability August-21 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office 2019 on Mac OSX according to Microsoft security
  updates August 2021" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to errors in handling
  Microsoft Word software for Mac OS X" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to execute arbitrary code and disclose the information." );
	script_tag( name: "affected", value: "Microsoft Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to version 16.52 (Build 21080801)
  for Microsoft Office 2019. Please see the references for more information." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac" );
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
	if(version_in_range( version: vers, test_version: "16.17.0", test_version2: "16.51" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "16.52 (Build 21080801)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

