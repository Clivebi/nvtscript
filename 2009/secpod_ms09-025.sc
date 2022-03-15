if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900669" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-10 16:35:14 +0200 (Wed, 10 Jun 2009)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1123", "CVE-2009-1124", "CVE-2009-1125", "CVE-2009-1126", "CVE-2009-1808" );
	script_bugtraq_id( 35121, 35238, 35240, 35120 );
	script_name( "Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (968537)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1544" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-025" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code with
  elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "Several flaws arise as the Windows kernel does not properly validate changes
  in certain kernel objects, pointers/input passed from user mode, arguments
  passed to system calls when editing a specific desktop parameter." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-025." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "968537" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Win32k.sys" );
	if(!sysVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "5.0.2195.7279" )){
		report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.0.2195.7279", install_path: sysPath );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: sysVer, test_version: "5.1.2600.3556" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.3556", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: sysVer, test_version: "5.1.2600.5796" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.5796", install_path: sysPath );
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
				if(version_is_less( version: sysVer, test_version: "5.2.3790.4497" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4497", install_path: sysPath );
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
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Win32k.sys" );
	if(!sysVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6001.18246" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18246", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6002.18023" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18023", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2008: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6001.18246" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18246", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18023" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18023", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

