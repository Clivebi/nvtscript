if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901182" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)" );
	script_cve_id( "CVE-2011-0086", "CVE-2011-0087", "CVE-2011-0088", "CVE-2011-0089", "CVE-2011-0090" );
	script_bugtraq_id( 46141, 46148, 46147, 46149, 46150 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2479628)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2479628" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0325" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-012" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow local attackers to gain elevated
  privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaws are caused by input validation errors, improper pointer validation,
  pointer confusions, and memory corruption errors in the Windows kernel-mode
  drivers 'win32k.sys' when processing data supplied from user mode to kernel
  mode, which could allow malicious users to execute arbitrary code with kernel
  privileges." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-012." );
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
if(hotfix_missing( name: "2479628" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Win32k.sys" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.6064" )){
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
			if(version_is_less( version: sysVer, test_version: "5.2.3790.4813" )){
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
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_in_range( version: sysVer, test_version: "6.0.6001.18000", test_version2: "6.0.6001.18572" ) || version_in_range( version: sysVer, test_version: "6.0.6001.22000", test_version2: "6.0.6001.22823" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_in_range( version: sysVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18364" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22559" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(version_is_less( version: sysVer, test_version: "6.1.7600.16732" ) || version_in_range( version: sysVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.20872" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17534" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21634" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}
