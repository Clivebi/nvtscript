if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902783" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 51296 );
	script_cve_id( "CVE-2012-0001" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "creation_date", value: "2012-01-11 10:01:06 +0530 (Wed, 11 Jan 2012)" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_name( "Microsoft Windows Kernel Security Feature Bypass Vulnerability (2644615)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2644615" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1026493" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-001" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code by
  leveraging memory corruption vulnerabilities in Windows applications." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error in the way the kernel (ntdll.dll) loads
  structured exception handling tables and allows bypassing the SafeSEH
  security mechanism. This facilitates easier exploitation of other
  vulnerabilities in affected applications to execute code." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-001." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3, winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2644615" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ntdll.dll" );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( win2003: 3 ) > 0 ){
	SP = get_kb_item( "SMB/Win2003/ServicePack" );
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "5.2.3790.4937" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
		SP = get_kb_item( "SMB/WinVista/ServicePack" );
		if(!SP){
			SP = get_kb_item( "SMB/Win2008/ServicePack" );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: dllVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18540" ) || version_in_range( version: dllVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22741" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 2 ) > 0){
			if(version_is_less( version: dllVer, test_version: "6.1.7600.16915" ) || version_in_range( version: dllVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21091" ) || version_in_range( version: dllVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17724" ) || version_in_range( version: dllVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21860" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

