if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900740" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0232", "CVE-2010-0233" );
	script_bugtraq_id( 37864 );
	script_name( "Microsoft Windows Kernel Could Allow Elevation of Privilege (977165)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/0179" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/979682" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code with
  kernel-level privilege." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "- Windows Kernel is not properly handling certain exceptions, which can be
    exploited to execute arbitrary code with kernel privileges.

  - Windows Kernel is not correctly resetting a pointer when freeing memory,
    which can be exploited to trigger a double-free condition." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-015." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-015" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3, win7: 1, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "977165" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	exeVer = fetch_file_version( sysPath: sysPath, file_name: "ntoskrnl.exe" );
	if(!exeVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: exeVer, test_version: "5.0.2195.7364" )){
		report = report_fixed_ver( installed_version: exeVer, fixed_version: "5.0.2195.7364", install_path: sysPath );
		security_message( port: 0, data: report );
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: exeVer, test_version: "5.1.2600.3654" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "5.1.2600.3654", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: exeVer, test_version: "5.1.2600.5913" )){
					report = report_fixed_ver( installed_version: exeVer, fixed_version: "5.1.2600.5913", install_path: sysPath );
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
				if(version_is_less( version: exeVer, test_version: "5.2.3790.4637" )){
					report = report_fixed_ver( installed_version: exeVer, fixed_version: "5.2.3790.4637", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	exeVer = fetch_file_version( sysPath: sysPath, file_name: "ntoskrnl.exe" );
	if(!exeVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: exeVer, test_version: "6.0.6001.18377" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6001.18377", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: exeVer, test_version: "6.0.6002.18160" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6002.18160", install_path: sysPath );
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
			if(version_is_less( version: exeVer, test_version: "6.0.6001.18377" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6001.18377", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: exeVer, test_version: "6.0.6002.18160" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6002.18160", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 1 ) > 0){
			if(version_is_less( version: exeVer, test_version: "6.1.7600.16481" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.1.7600.16481", install_path: sysPath );
				security_message( port: 0, data: report );
			}
		}
	}
}

