if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900877" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-14 16:47:08 +0200 (Wed, 14 Oct 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-2524" );
	script_bugtraq_id( 36593 );
	script_name( "Microsoft Windows LSASS Denial of Service Vulnerability (975467)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/975467" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2894" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-059" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a Denial of
  Service on the victim's system." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "This issue is caused by an integer underflow error in the Windows NTLM
  implementation in LSASS (Local Security Authority Subsystem Service) when
  processing malformed packets during the authentication process, which could
  allow attackers to cause an affected system to automatically reboot." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-059." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-059" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win7: 1, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "968389" ) == 1){
	exit( 0 );
}
if(hotfix_missing( name: "975467" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Msv1_0.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if( ContainsString( SP, "Service Pack 2" ) ){
		if(version_is_less( version: dllVer, test_version: "5.1.2600.3625" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.3625", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	else {
		if(ContainsString( SP, "Service Pack 3" )){
			if(version_is_less( version: dllVer, test_version: "5.1.2600.5876" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.5876", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2003: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "5.2.3790.4587" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.2.3790.4587", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Msv1_0.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6001.18330" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18330", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6002.18111" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18111", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if( hotfix_check_sp( win2008: 3 ) > 0 ){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6001.18330" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18330", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6002.18111" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18111", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 1 ) > 0){
			if(version_is_less( version: dllVer, test_version: "6.1.7600.16420" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.1.7600.16420", install_path: sysPath );
				security_message( port: 0, data: report );
			}
		}
	}
}

