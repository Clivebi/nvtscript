if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901166" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3333", "CVE-2010-3334", "CVE-2010-3335", "CVE-2010-3336", "CVE-2010-3337" );
	script_bugtraq_id( 44652, 44656, 44659, 44660, 42628 );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities (2423930)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Office XP Service Pack 3

  - Microsoft Office 2003 Service Pack 3

  - Microsoft Office 2007 Service Pack 2

  - Microsoft Office 2010" );
	script_tag( name: "insight", value: "Multiple flaws are caused by,

  - a stack overflow error when processing malformed Rich Text Format data.

  - a memory corruption error when processing Office Art Drawing records in
    Office files.

  - a memory corruption error when handling drawing exceptions.

  - a memory corruption error when handling SPID data in Office documents.

  - an error when loading certain libraries from the current working directory." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-087." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2923" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-087" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
func FileVer( file, path ){
	share = ereg_replace( pattern: "([A-Za-z]):.*", replace: "\\1$", string: path );
	if(IsMatchRegexp( share, "[a-z]\\$" )){
		share = toupper( share );
	}
	file = ereg_replace( pattern: "[A-Za-z]:(.*)", replace: "\\1", string: path + file );
	ver = GetVer( file: file, share: share );
	return ver;
}
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^1[0124]\\." )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(!path){
		exit( 0 );
	}
	for ver in make_list( "OFFICE10",
		 "OFFICE11",
		 "OFFICE12",
		 "OFFICE14" ) {
		offPath = path + "\\Microsoft Shared\\" + ver;
		dllVer = FileVer( file: "\\Mso.dll", path: offPath );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "10.0", test_version2: "10.0.6866.9" ) || version_in_range( version: dllVer, test_version: "11.0", test_version2: "11.0.8328.9" ) || version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6545.5003" ) || version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.5128.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

