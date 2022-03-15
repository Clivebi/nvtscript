if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817853" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_cve_id( "CVE-2020-17128", "CVE-2020-17123", "CVE-2020-17124", "CVE-2020-17119" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 18:25:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-09 10:39:05 +0530 (Wed, 09 Dec 2020)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Vulnerabilities Dec20 - Mac OS X" );
	script_tag( name: "summary", value: "This host is missing a critical security update for Microsoft
  Office on Mac OSX according to Microsoft security update December 2020." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to microsoft excel, outlook and
  powerpoint software fails to properly handle specially crafted Office file." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to execute
  arbitrary code in the context of the current user and disclose sensitive information." );
	script_tag( name: "affected", value: "Microsoft Office 2019 on Mac OS X." );
	script_tag( name: "solution", value: "No known solution is available as of 08th July, 2021.
  Information regarding this issue will be updated once solution details are available.

  The security update for Microsoft Office 2019 for Mac is not immediately available. Please see the
  references for more information." );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
	if(version_in_range( version: vers, test_version: "16.17.0", test_version2: "16.43" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "None" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

