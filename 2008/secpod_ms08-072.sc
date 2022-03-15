if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900063" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4024", "CVE-2008-4025", "CVE-2008-4026", "CVE-2008-4027", "CVE-2008-4028", "CVE-2008-4030", "CVE-2008-4031", "CVE-2008-4837" );
	script_bugtraq_id( 32579, 32580, 32581, 32583, 32584, 32585, 32594, 32642 );
	script_name( "Vulnerabilities in Microsoft Office Word Could Allow Remote Code Execution (957173)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-072" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc", "secpod_ms_office_detection_900025.sc" );
	script_mandatory_keys( "MS/Office/Ver", "SMB/Office/Word/Version" );
	script_tag( name: "impact", value: "Successful exploitation could execute arbitrary code on the remote system
  and corrupt memory via a specially crafted Excel Spreadsheet (XLS) file." );
	script_tag( name: "affected", value: "Microsoft Office 2K/XP/2003/2007." );
	script_tag( name: "insight", value: "Microsoft office is prone to multiple vulnerabilities. Please see the
  references for more information." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-072." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^(9|1[0-2])\\." )){
	wordVer = get_kb_item( "SMB/Office/Word/Version" );
	if(!wordVer || !IsMatchRegexp( wordVer, "^(9|1[0-2])\\." )){
		exit( 0 );
	}
	if( version_in_range( version: wordVer, test_version: "9.0", test_version2: "9.0.0.8973" ) ){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if( version_in_range( version: wordVer, test_version: "10.0", test_version2: "10.0.6849" ) ){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if( version_in_range( version: wordVer, test_version: "11.0", test_version2: "11.0.8236" ) ){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			else {
				if(version_in_range( version: wordVer, test_version: "12.0", test_version2: "12.0.6331.4999" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

