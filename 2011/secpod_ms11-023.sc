if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902364" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0107", "CVE-2011-0977" );
	script_bugtraq_id( 47246, 46227 );
	script_name( "Microsoft Office Remote Code Execution Vulnerabilities (2489293)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0942" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-023" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a Word file from a network share or via a malicious Office document." );
	script_tag( name: "affected", value: "- Microsoft Office XP Service Pack 3

  - Microsoft Office 2003 Service Pack 3

  - Microsoft Office 2007 Service Pack 2" );
	script_tag( name: "insight", value: "The flaws are caused by,

  - an error in a shared component that incorrectly restricts the path used for
    loading external libraries.

  - an error when dereferencing data structures within Office files containing
    graphic objects." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-023." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(officeVer && IsMatchRegexp( officeVer, "^1[012]\\." )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(!path){
		exit( 0 );
	}
	for ver in make_list( "OFFICE10",
		 "OFFICE11",
		 "OFFICE12" ) {
		offPath = path + "\\Microsoft Shared\\" + ver;
		dllVer = fetch_file_version( sysPath: offPath, file_name: "Mso.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "10.0", test_version2: "10.0.6869.9" ) || version_in_range( version: dllVer, test_version: "11.0", test_version2: "11.0.8332.9" ) || version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6554.5000" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

