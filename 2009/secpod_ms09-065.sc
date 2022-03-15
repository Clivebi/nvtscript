if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900886" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1127", "CVE-2009-2513", "CVE-2009-2514" );
	script_bugtraq_id( 36939, 36941, 36029 );
	script_name( "Microsoft Windows Kernel-Mode Drivers Multiple Vulnerabilities (969947)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/969947" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3191" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-065" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to remote attackers to compromise
  a vulnerable system or by local attackers to gain elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "- An error in the Win32k kernel-mode driver 'Win32k.sys' when parsing
    font code can be exploited to execute arbitrary code if a user
    views content rendered in a specially crafted Embedded OpenType (EOT)
    font, when a user visits a malicious web site.

  - Some vulnerabilities in the Win32k kernel-mode driver can be exploited by
    malicious, local users to gain escalated privileges.

  - An error in the Win32k kernel-mode driver 'Win32k.sys' when handling input
    passed through the kernel component of GDI (Graphics Device Interface) can
    be exploited to execute arbitrary code in kernel mode." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-065." );
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
if(hotfix_missing( name: "969947" ) == 0){
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
	if(version_is_less( version: sysVer, test_version: "5.0.2195.7322" )){
		report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.0.2195.7322", install_path: sysPath );
		security_message( port: 0, data: report );
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: sysVer, test_version: "5.1.2600.3614" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.3614", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: sysVer, test_version: "5.1.2600.5863" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.5863", install_path: sysPath );
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
				if(version_is_less( version: sysVer, test_version: "5.2.3790.4571" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4571", install_path: sysPath );
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
		if(version_is_less( version: sysVer, test_version: "6.0.6001.18311" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18311", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6002.18091" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18091", install_path: sysPath );
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
			if(version_is_less( version: sysVer, test_version: "6.0.6001.18311" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18311", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18091" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18091", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

