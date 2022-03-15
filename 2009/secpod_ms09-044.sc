if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900813" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1133", "CVE-2009-1929" );
	script_bugtraq_id( 35971, 35973 );
	script_name( "Microsoft Remote Desktop Connection Remote Code Execution Vulnerability (969706)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/970927" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2238" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-044" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code which may
  result in heap-based buffer overflow on the affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 2k  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2k3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "- Error exists when processing specific parameters returned by the RDP server,
    which could be exploited to cause a heap-based buffer overflow by tricking a
    user into connecting to a malicious RDP server.

  - An heap-based buffer overflow error in the Remote Desktop Web Connection
    ActiveX control when processing malformed parameters, which can be exploited
    via specially crafted web page." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-044." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-044" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "958469" ) == 0 ) || ( hotfix_missing( name: "958470" ) == 0 ) || ( hotfix_missing( name: "958471" ) == 0 ) || ( hotfix_missing( name: "956744" ) == 0 )){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Mstscax.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "5.1.2600.3581" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: dllVer, test_version: "5.1.2600.3581" ) || version_in_range( version: dllVer, test_version: "6.0.6000.00000", test_version2: "6.0.6000.16864" ) || version_in_range( version: dllVer, test_version: "6.0.6001.00000", test_version2: "6.0.6001.22442" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: dllVer, test_version: "5.1.2600.3581" ) || version_in_range( version: dllVer, test_version: "6.0.6001.00000", test_version2: "6.0.6001.18265" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
	else {
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_is_less( version: dllVer, test_version: "5.2.3790.4524" ) || version_in_range( version: dllVer, test_version: "6.0", test_version2: "6.0.6000.16864" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Mstscax.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6001.18266" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6002.18045" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2008: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6001.18266" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6002.18045" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

