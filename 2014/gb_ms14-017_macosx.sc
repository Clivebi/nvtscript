if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804427" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-1757", "CVE-2014-1758", "CVE-2014-1761" );
	script_bugtraq_id( 66385, 66614, 66629 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 10:25:33 +0530 (Wed, 09 Apr 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities-2949660 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS14-017." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "insight", value: "Multiple flaws are due to an error within,

  - Microsoft Word when handling certain RTF-formatted data can be exploited to
  corrupt memory.

  - Microsoft Office File Format Converter when handling certain files can be
  exploited to corrupt memory.

  - Microsoft Word when handling certain files can be exploited to cause a
  stack-based buffer overflow." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system." );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
offVer = get_kb_item( "MS/Office/MacOSX/Ver" );
if(!offVer || !IsMatchRegexp( offVer, "^14\\." )){
	exit( 0 );
}
if(version_in_range( version: offVer, test_version: "14.0", test_version2: "14.4.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

