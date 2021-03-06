if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900365" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-10 19:23:54 +0200 (Wed, 10 Jun 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0563", "CVE-2009-0565" );
	script_bugtraq_id( 35188, 35190 );
	script_name( "Microsoft Office Word Remote Code Execution Vulnerabilities (969514)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/969514" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-027" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Ver", "MS/Office/Prdts/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Word document." );
	script_tag( name: "affected", value: "- Microsoft Word Viewer 2003

  - Microsoft Office 2K/XP/2003/2007" );
	script_tag( name: "insight", value: "The flaws are due to boundary errors when parsing certain records that can be
  exploited to cause a buffer overflow." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-027." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
wordVer = get_kb_item( "SMB/Office/Word/Version" );
if(officeVer && IsMatchRegexp( officeVer, "^(9|1[0-2])\\." )){
	if(!wordVer){
		exit( 0 );
	}
	if( version_in_range( version: wordVer, test_version: "9.0", test_version2: "9.0.0.8978" ) ){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if( version_in_range( version: wordVer, test_version: "10.0", test_version2: "10.0.6853.0" ) ){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if( version_in_range( version: wordVer, test_version: "11.0", test_version2: "11.0.8306.0" ) ){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			else {
				if(version_in_range( version: wordVer, test_version: "12.0", test_version2: "12.0.6504.4999" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}
if(IsMatchRegexp( wordVer, "^12\\." )){
	wordcnvVer = get_kb_item( "SMB/Office/WordCnv/Version" );
	if(!wordcnvVer){
		exit( 0 );
	}
	if(version_in_range( version: wordcnvVer, test_version: "12.0", test_version2: "12.0.6500.4999" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
wordviewVer = get_kb_item( "SMB/Office/WordView/Version" );
if(wordviewVer){
	if(version_in_range( version: wordviewVer, test_version: "11.0", test_version2: "11.0.8306.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

