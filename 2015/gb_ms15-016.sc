if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805137" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-0061" );
	script_bugtraq_id( 72456 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-02-11 11:58:29 +0530 (Wed, 11 Feb 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Graphics Component Information Disclosure Vulnerability (3029944)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-016." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to improper handling uninitialized
  memory when parsing certain, specially crafted TIFF image format files." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose certain sensitive information." );
	script_tag( name: "affected", value: "- Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3029944" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-016" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Windowscodecs.dll" );
if(!dllVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(version_is_less( version: dllVer, test_version: "7.0.6002.19281" ) || version_in_range( version: dllVer, test_version: "7.0.6002.23000", test_version2: "7.0.6002.23590" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
	if(version_in_range( version: dllVer, test_version: "6.1.7601.00000", test_version2: "6.1.7601.18715" ) || version_in_range( version: dllVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22921" ) || version_in_range( version: dllVer, test_version: "6.2.9200.00000", test_version2: "6.2.9200.17225" ) || version_in_range( version: dllVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.21342" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
	if(version_in_range( version: dllVer, test_version: "6.2.9200.00000", test_version2: "6.2.9200.17227" ) || version_in_range( version: dllVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.21344" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
	if(version_is_less( version: dllVer, test_version: "6.3.9600.17631" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

