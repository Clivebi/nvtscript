if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902495" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-1983" );
	script_bugtraq_id( 50956 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-14 11:40:47 +0530 (Wed, 14 Dec 2011)" );
	script_name( "Microsoft Office Remote Code Execution Vulnerability (2590602)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2596785" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2589320" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-089" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "MS/Office/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user." );
	script_tag( name: "affected", value: "- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 1 and prior" );
	script_tag( name: "insight", value: "The flaw is due to a use-after-free error when parsing Word documents
  and can be exploited to dereference already freed memory." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-089." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
officeVer = get_kb_item( "MS/Office/Ver" );
if(!officeVer){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^1[24]\\." )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(!path){
		exit( 0 );
	}
	for ver in make_list( "OFFICE12",
		 "OFFICE14" ) {
		offPath = path + "\\Microsoft Shared\\" + ver;
		dllVer = fetch_file_version( sysPath: offPath, file_name: "msptls.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6654.4999" ) || version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6112.4999" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

