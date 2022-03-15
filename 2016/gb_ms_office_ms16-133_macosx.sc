CPE = "cpe:/a:microsoft:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809727" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-7213", "CVE-2016-7228", "CVE-2016-7229", "CVE-2016-7231", "CVE-2016-7232" );
	script_bugtraq_id( 93993, 93996, 93995, 93994, 94005 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-11-17 11:34:42 +0530 (Thu, 17 Nov 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Remote Code Execution Vulnerabilities-3199168(Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-133" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as office software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Office 2011 on Mac OS X

  - Microsoft Office 2016 on Mac OS X" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3198807" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3198798" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-133" );
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
if(!IsMatchRegexp( offVer, "^1[45]\\." )){
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^14\\." ) && version_is_less( version: offVer, test_version: "14.7.0" )){
	report = "File version:     " + offVer + "\n" + "Vulnerable range: 14.1.0 - 14.6.9" + "\n";
	security_message( data: report );
	exit( 0 );
}
if(IsMatchRegexp( offVer, "^15\\." ) && version_is_less( version: offVer, test_version: "15.28" )){
	report = "File version:     " + offVer + "\n" + "Vulnerable range: 15.0 - 15.27" + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

