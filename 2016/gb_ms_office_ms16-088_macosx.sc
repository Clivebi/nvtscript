CPE = "cpe:/a:microsoft:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807867" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-3280", "CVE-2016-3281", "CVE-2016-3282", "CVE-2016-3284" );
	script_bugtraq_id( 91582, 91588, 91589, 91594 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-07-13 16:17:51 +0530 (Wed, 13 Jul 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Remote Code Execution Vulnerabilities-3170008(Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-088" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as office software
  fails to properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers  to run arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "- Microsoft Office 2011 on Mac OS X

  - Microsoft Office 2016 on Mac OS X" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3170460" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3170463" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-088" );
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
if(IsMatchRegexp( offVer, "^14\\." ) && version_is_less( version: offVer, test_version: "14.6.6" )){
	report = "File version:     " + offVer + "\n" + "Vulnerable range: 14.1.0 - 14.6.5 " + "\n";
	security_message( data: report );
}
if(IsMatchRegexp( offVer, "^15\\." ) && version_is_less( version: offVer, test_version: "15.24.0" )){
	report = "File version:     " + offVer + "\n" + "Vulnerable range: 15.0 - 15.23.0 " + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

