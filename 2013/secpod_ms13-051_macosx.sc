if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902977" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-1331" );
	script_bugtraq_id( 60408 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-06-12 09:30:35 +0530 (Wed, 12 Jun 2013)" );
	script_name( "Microsoft Office Remote Code Execution Vulnerability-2839571 (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028650" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-051" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gb_microsoft_office_detect_macosx.sc" );
	script_mandatory_keys( "MS/Office/MacOSX/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user." );
	script_tag( name: "affected", value: "Microsoft Office 2011 on Mac OS X." );
	script_tag( name: "insight", value: "The flaw is due to an error when processing PNG files and can be exploited
  to cause a buffer overflow via a specially crafted file." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-051." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
offVer = get_kb_item( "MS/Office/MacOSX/Ver" );
if(!offVer || !IsMatchRegexp( offVer, "^14\\." )){
	exit( 0 );
}
if(version_in_range( version: offVer, test_version: "14.0", test_version2: "14.3.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

