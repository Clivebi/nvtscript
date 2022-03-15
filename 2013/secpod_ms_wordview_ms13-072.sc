if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903403" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849", "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853", "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857", "CVE-2013-3858" );
	script_bugtraq_id( 62162, 62165, 62168, 62169, 62170, 62171, 62216, 62217, 62220, 62222, 62223, 62224, 62226 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-09-11 17:10:50 +0530 (Wed, 11 Sep 2013)" );
	script_name( "Microsoft Office Word Viewer Remote Code Execution Vulnerabilities (2845537)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-072." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws are due to error exists when processing XML data and some
  unspecified errors." );
	script_tag( name: "affected", value: "Microsoft Word Viewer 2003." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2817683" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-072" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/WordView/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(wordviewVer && IsMatchRegexp( wordviewVer, "^11.*" )){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8405" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

