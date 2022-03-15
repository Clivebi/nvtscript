CPE = "cpe:/a:microsoft:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807367" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0141", "CVE-2016-3357" );
	script_bugtraq_id( 92903, 92786 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-09-14 14:45:19 +0530 (Wed, 14 Sep 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Remote Code Execution Vulnerabilities-3185852(Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-107" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3186807" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3186805" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-107" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!offVer = get_kb_item( "MS/Office/MacOSX/Ver" )){
	exit( 0 );
}
if(offVer && IsMatchRegexp( offVer, "^(14\\.)" )){
	if(version_is_less( version: offVer, test_version: "14.6.7" )){
		report = "File version:     " + offVer + "\n" + "Vulnerable range: 14.1.0 - 14.6.7 " + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( offVer, "^(15\\.)" ) && version_is_less( version: offVer, test_version: "15.25.0" )){
	report = "File version:     " + offVer + "\n" + "Vulnerable range: 15.0 - 15.25.0 " + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

