if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902609" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)" );
	script_cve_id( "CVE-2011-1281", "CVE-2011-1282", "CVE-2011-1283", "CVE-2011-1284", "CVE-2011-1870" );
	script_bugtraq_id( 48588, 48598, 48604, 48606, 48605 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows CSRSS Privilege Escalation Vulnerabilities (2507938)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2507938" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-056" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow local attacker to execute arbitrary
  code on the system with elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaws are due to:

  - memory corruption error related to AllocConsole

  - memory corruption error related to SrvSetConsoleLocalEUDC

  - improper verification by SrvSetConsoleNumberOfCommand

  - integer overflow in SrvWriteConsoleOutput" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-056." );
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
if(hotfix_missing( name: "2507938" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\winsrv.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.6104" )){
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
			if(version_is_less( version: sysVer, test_version: "5.2.3790.4860" )){
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
				if(version_in_range( version: sysVer, test_version: "6.0.6001.18000", test_version2: "6.0.6001.18637" ) || version_in_range( version: sysVer, test_version: "6.0.6001.22000", test_version2: "6.0.6001.22903" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_in_range( version: sysVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18455" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22627" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(version_in_range( version: sysVer, test_version: "6.1.7600.16000", test_version2: "6.1.7600.16815" ) || version_in_range( version: sysVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.20977" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17616" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21727" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

