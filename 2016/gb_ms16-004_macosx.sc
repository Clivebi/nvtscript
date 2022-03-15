if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806195" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-0010", "CVE-2016-0012", "CVE-2016-0035" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-01-13 12:53:57 +0530 (Wed, 13 Jan 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Multiple Vulnerabilities (3124585) (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-004" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Improper handling of files and objects in the memory.

  - Insufficient sanitization of user supplied input by Outlook for Mac." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute arbitrary code, conduct spoofing attacks, perform unauthorized
  actions and some other attacks." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3133699" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-004" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
offVer = get_kb_item( "MS/Office/MacOSX/Ver" );
if(offVer && IsMatchRegexp( offVer, "^(14\\.)" )){
	if(version_is_less( version: offVer, test_version: "14.6.0" )){
		report = "File version:     " + offVer + "\n" + "Vulnerable range: Less than 14.6.0" + "\n";
		security_message( data: report );
	}
}
exit( 99 );

