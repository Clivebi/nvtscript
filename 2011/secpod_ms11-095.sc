if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902768" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3406" );
	script_bugtraq_id( 50959 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-13 11:15:13 +0530 (Tue, 13 Dec 2011)" );
	script_name( "MS Windows Active Directory Remote Code Execution Vulnerability (2640045)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2626416" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2621146" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-095" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow the remote attackers to execute arbitrary
  code with Network Service privileges. Failed exploit attempts may result in a
  denial-of-service condition." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2003 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error within the implementations of Active
  Directory, Active Directory Application Mode (ADAM), and Active Directory
  Lightweight Directory Service (AD LDS) when handling certain queries." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-095" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
if(( hotfix_missing( name: "2621146" ) == 1 ) && registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Performance" )){
	ntdsaVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ntdsa.dll" );
	if(ntdsaVer != NULL){
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_is_less( version: ntdsaVer, test_version: "5.2.3790.4929" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
if(( hotfix_missing( name: "2626416" ) == 1 ) && registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\ADAM\\Linkage" )){
	adamdsaVer = fetch_file_version( sysPath: sysPath, file_name: "ADAM\\Adamdsa.dll" );
	if(adamdsaVer != NULL){
		if(hotfix_check_sp( xp: 4, win2003: 3 ) > 0){
			XPSP = get_kb_item( "SMB/WinXP/ServicePack" );
			k3SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(( ContainsString( XPSP, "Service Pack 3" ) ) || ( ContainsString( k3SP, "Service Pack 2" ) )){
				if(version_is_less( version: adamdsaVer, test_version: "1.1.3790.4921" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
if(( hotfix_missing( name: "2621146" ) == 0 )){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Ntdsai.dll" );
if( !dllVer ){
	exit( 0 );
}
else {
	if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
		SP = get_kb_item( "SMB/WinVista/ServicePack" );
		if(!SP){
			SP = get_kb_item( "SMB/Win2008/ServicePack" );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: dllVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18531" ) || version_in_range( version: dllVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22730" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 2 ) > 0){
			if(version_is_less( version: dllVer, test_version: "6.1.7600.16900" ) || version_in_range( version: dllVer, test_version: "6.1.7600.21000", test_version2: "6.1.7600.21070" ) || version_in_range( version: dllVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17708" ) || version_in_range( version: dllVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21840" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

