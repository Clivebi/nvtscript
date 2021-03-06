if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900973" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3135" );
	script_bugtraq_id( 36950 );
	script_name( "Microsoft Office Word Remote Code Execution Vulnerability (976307)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Prdts/Installed" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3194" );
	script_tag( name: "impact", value: "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Word document." );
	script_tag( name: "affected", value: "- Microsoft Office XP/2003

  - Microsoft Word Viewer 2003" );
	script_tag( name: "insight", value: "The flaws are due to memory corruption error when processing a malformed
  record within a Word document." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-068." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-068" );
	exit( 0 );
}
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
offVer = get_kb_item( "MS/Office/Ver" );
if(IsMatchRegexp( offVer, "^1[01]\\." )){
	wordVer = get_kb_item( "SMB/Office/Word/Version" );
	if(IsMatchRegexp( wordVer, "^1[01]\\." )){
		if(version_in_range( version: wordVer, test_version: "10.0", test_version2: "10.0.6855.9" ) || version_in_range( version: wordVer, test_version: "11.0", test_version2: "11.0.8312.9" )){
			report = report_fixed_ver( installed_version: wordVer, vulnerable_range: "10.0 - 10.0.6855.9, 11.0 - 11.0.8312.9" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(IsMatchRegexp( wordviewVer, "^11\\." )){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8312.9" )){
		report = report_fixed_ver( installed_version: wordviewVer, vulnerable_range: "11.0 - 11.0.8312.9" );
		security_message( port: 0, data: report );
	}
}

