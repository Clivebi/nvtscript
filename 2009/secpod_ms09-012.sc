if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900094" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-15 18:21:29 +0200 (Wed, 15 Apr 2009)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-1436", "CVE-2009-0078", "CVE-2009-0079", "CVE-2009-0080" );
	script_bugtraq_id( 28833, 34442, 34443, 34444 );
	script_name( "Vulnerabilities in Windows Could Allow Elevation of Privilege (959454)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code by
  gaining elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1 and prior" );
	script_tag( name: "insight", value: "- Microsoft Distributed Transaction Coordinator (MSDTC) transaction facility
    allowing the NetworkService token to be obtained and used when making an
    RPC call.

  - Windows Management Instrumentation (WMI) provider improperly isolating
    processes that run under the NetworkService or LocalService accounts.

  - RPCSS service improperly isolating processes that run under the
    NetworkService or LocalService accounts.

  - Windows placing incorrect access control lists (ACLs) on threads in the
    current ThreadPool." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-012." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/959454" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-012" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 2, win2008: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "952004" ) == 0 || hotfix_missing( name: "956572" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Msdtcprx.dll" );
	if(sysVer){
		if(hotfix_check_sp( win2k: 5 ) > 0){
			if(version_is_less( version: sysVer, test_version: "2000.2.3549.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		if(hotfix_check_sp( xp: 4 ) > 0){
			SP = get_kb_item( "SMB/WinXP/ServicePack" );
			if( ContainsString( SP, "Service Pack 2" ) ){
				if(version_is_less( version: sysVer, test_version: "2001.12.4414.320" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 3" )){
					if(version_is_less( version: sysVer, test_version: "2001.12.4414.706" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(version_is_less( version: sysVer, test_version: "2001.12.4720.3180" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_is_less( version: sysVer, test_version: "2001.12.4720.4340" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Msdtcprx.dll" );
	if(dllVer){
		if( hotfix_check_sp( winVista: 2 ) > 0 ){
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_is_less( version: dllVer, test_version: "2001.12.6931.18085" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
		}
		else {
			if(hotfix_check_sp( win2008: 2 ) > 0){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
				if(ContainsString( SP, "Service Pack 1" )){
					if(version_is_less( version: dllVer, test_version: "2001.12.6931.18085" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
		}
	}
}

