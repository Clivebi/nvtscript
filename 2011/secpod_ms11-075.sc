if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902746" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)" );
	script_cve_id( "CVE-2011-1247" );
	script_bugtraq_id( 49976 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Active Accessibility Remote Code Execution Vulnerability (2623699)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-075" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the user running the vulnerable application." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to a way that the Microsoft Active Accessibility
  component handles the loading of DLL files. This can be exploited to load
  arbitrary libraries by tricking a user into opening a file located on a
  remote WebDAV or SMB share." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS11-075." );
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
if(( hotfix_missing( name: "2564958" ) == 0 )){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Oleacc.dll" );
if(dllVer){
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if(ContainsString( SP, "Service Pack 3" )){
			if(version_is_less( version: dllVer, test_version: "7.0.2600.6153" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if( hotfix_check_sp( win2003: 3 ) > 0 ){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_is_less( version: dllVer, test_version: "7.0.3790.4909" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				SP = get_kb_item( "SMB/WinVista/ServicePack" );
				if(!SP){
					SP = get_kb_item( "SMB/Win2008/ServicePack" );
				}
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_is_less( version: dllVer, test_version: "7.0.6002.18508" ) || version_in_range( version: dllVer, test_version: "7.0.6002.22000", test_version2: "7.0.6002.22705" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Oleaut32.dll" );
if(dllVer){
	if(hotfix_check_sp( win7: 2 ) > 0){
		if(version_is_less( version: dllVer, test_version: "6.1.7600.16872" ) || version_in_range( version: dllVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21035" ) || version_in_range( version: dllVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17675" ) || version_in_range( version: dllVer, test_version: "6.1.7601.20000", test_version2: "6.1.7601.21801" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

