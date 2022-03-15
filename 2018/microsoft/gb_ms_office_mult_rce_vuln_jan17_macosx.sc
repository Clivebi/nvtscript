if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812729" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2018-0792", "CVE-2018-0794", "CVE-2018-0793", "CVE-2018-0819" );
	script_bugtraq_id( 102381, 102373, 102375 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-11 14:22:59 +0530 (Thu, 11 Jan 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Remote Code Execution Vulnerabilities - Jan18 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office 2016 on Mac OSX according to Microsoft security
  update January 2018" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Microsoft office software fails to properly handle objects in memory.

  - Microsoft outlook improperly parses specially crafted email messages." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to run arbitrary code in the context of the current user. If the current user
  is logged on with administrative user rights, an attacker could take control
  of the affected system." );
	script_tag( name: "affected", value: "Microsoft Office 2016 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Microsoft Office 2016 version
  16.9.0 (Build 18011602) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.office.com/en-us/article/Release-notes-for-Office-2016-for-Mac-ed2da564-6d53-4542-9954-7e3209681a41" );
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
if(IsMatchRegexp( offVer, "^1[56]\\." ) && version_is_less( version: offVer, test_version: "16.9.0" )){
	report = report_fixed_ver( installed_version: offVer, fixed_version: "16.9.0" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

