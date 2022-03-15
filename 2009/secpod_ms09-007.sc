if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900087" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-11 16:41:30 +0100 (Wed, 11 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:N" );
	script_cve_id( "CVE-2009-0085" );
	script_bugtraq_id( 34015 );
	script_name( "Vulnerability in SChannel Could Allow Spoofing (960225)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-007" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Attacker who successfully exploited would be able to authenticate to a
  server using only an authorized user's digital certificate and without
  the associated private key." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1 and prior" );
	script_tag( name: "insight", value: "Spoofing flaw exists in the Microsoft Windows SChannel (Secure Channel)
  authentication component when using certificate based authentication." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-007." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 2, win2008: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "960225" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Schannel.dll" );
	if(sysVer){
		if(hotfix_check_sp( win2k: 5 ) > 0){
			if(version_is_less( version: sysVer, test_version: "5.1.2195.7213" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2195.7213", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(hotfix_check_sp( xp: 4 ) > 0){
			SP = get_kb_item( "SMB/WinXP/ServicePack" );
			if( ContainsString( SP, "Service Pack 2" ) ){
				if(version_is_less( version: sysVer, test_version: "5.1.2600.3487" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.3487", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 3" )){
					if(version_is_less( version: sysVer, test_version: "5.1.2600.5721" )){
						report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.5721", install_path: sysPath );
						security_message( port: 0, data: report );
					}
					exit( 0 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(version_is_less( version: sysVer, test_version: "5.2.3790.3293" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.3293", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_is_less( version: sysVer, test_version: "5.2.3790.4458" )){
						report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4458", install_path: sysPath );
						security_message( port: 0, data: report );
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
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "Schannel.dll" );
	if(dllVer){
		if( hotfix_check_sp( winVista: 2 ) > 0 ){
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_is_less( version: dllVer, test_version: "6.0.6001.18175" )){
					report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18175", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
		}
		else {
			if(hotfix_check_sp( win2008: 2 ) > 0){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
				if(ContainsString( SP, "Service Pack 1" )){
					if(version_is_less( version: dllVer, test_version: "6.0.6001.18175" )){
						report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18175", install_path: sysPath );
						security_message( port: 0, data: report );
					}
					exit( 0 );
				}
			}
		}
	}
}

