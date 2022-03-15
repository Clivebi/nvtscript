if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902987" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3178" );
	script_bugtraq_id( 60978, 60932, 60938 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-07-11 11:32:39 +0530 (Thu, 11 Jul 2013)" );
	script_name( "Microsoft Silverlight Remote Code Execution Vulnerabilities-2861561 (Mac OS X)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2861561" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-052" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_ms_silverlight_detect_macosx.sc" );
	script_mandatory_keys( "MS/Silverlight/MacOSX/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary code,
  bypass security mechanism and take complete control of an affected system." );
	script_tag( name: "affected", value: "Microsoft Silverlight version 5 on Mac OS X." );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Improper handling of TrueType font and multidimensional arrays of
  small structures

  - Improper Handling of null pointer" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS13-052." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
slightVer = get_kb_item( "MS/Silverlight/MacOSX/Ver" );
if(!slightVer || !IsMatchRegexp( slightVer, "^5\\." )){
	exit( 0 );
}
if(version_in_range( version: slightVer, test_version: "5.1", test_version2: "5.1.20512" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

