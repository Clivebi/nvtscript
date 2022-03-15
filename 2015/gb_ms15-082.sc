if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805080" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-2472", "CVE-2015-2473" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-08-12 10:37:53 +0530 (Wed, 12 Aug 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows RDP Remote Code Execution Vulnerabilities (3080348)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-082." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A spoofing vulnerability exists when the Remote Desktop Session Host (RDSH)
    improperly validates certificates during authentication.

  - A remote code execution vulnerability exists when Microsoft Windows Remote
    Desktop Protocol client improperly handles the loading of certain specially
    crafted DLL files." );
	script_tag( name: "impact", value: "Successful exploitation will allow  attacker
  to take complete control of an affected system. An attacker could then install,
  programs, view, change, or delete data  or create new accounts with full user
  rights." );
	script_tag( name: "affected", value: "- Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3080348" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-082" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012R2: 1, win8: 1, win8x64: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Tsgqec.dll" );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if(version_in_range( version: dllVer, test_version: "6.1.7600.17000", test_version2: "6.1.7600.17232" ) || version_in_range( version: dllVer, test_version: "6.1.7600.21000", test_version2: "6.1.7600.21447" ) || version_in_range( version: dllVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18004" ) || version_in_range( version: dllVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23746" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
		if(version_in_range( version: dllVer, test_version: "6.3.9600.16000", test_version2: "6.3.9600.16414" ) || version_in_range( version: dllVer, test_version: "6.2.9200.16000", test_version2: "6.2.9200.16397" ) || version_in_range( version: dllVer, test_version: "6.1.7601.18000", test_version2: "6.1.7601.18917" ) || version_in_range( version: dllVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.23120" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ){
			if(version_in_range( version: dllVer, test_version: "6.2.9200.16000", test_version2: "6.2.9200.16383" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "6.3.9600.16000", test_version2: "6.3.9600.17414" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
		}
	}
}

