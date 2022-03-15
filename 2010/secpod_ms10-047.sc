if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902093" );
	script_version( "2021-08-11T13:58:23+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 13:58:23 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)" );
	script_bugtraq_id( 42211, 42213, 42221 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-1888", "CVE-2010-1889", "CVE-2010-1890" );
	script_name( "Microsoft Windows Kernel Privilege Elevation Vulnerabilities (981852)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to run arbitrary code in
  kernel level privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "Multiple errors exist due to:

  - The way kernel deals with specific thread creation attempts.

  - An error in initializing the objects while handling certain exceptions.

  - An error in validating access control lists on kernel objects." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS10-047." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Aug/1024307.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-047" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, winVista: 3, win7: 1, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "981852" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	exeVer = fetch_file_version( sysPath: sysPath, file_name: "ntoskrnl.exe" );
	if(!exeVer){
		exit( 0 );
	}
}
if(hotfix_check_sp( xp: 4 ) > 0){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_is_less( version: exeVer, test_version: "5.1.2600.5973" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "5.1.2600.5973", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
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
		if(version_is_less( version: exeVer, test_version: "6.0.6001.18488" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6001.18488", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: exeVer, test_version: "6.0.6002.18267" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6002.18267", install_path: sysPath );
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
			if(version_is_less( version: exeVer, test_version: "6.0.6001.18488" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6001.18488", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: exeVer, test_version: "6.0.6002.18267" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6002.18267", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 1 ) > 0){
			if(version_is_less( version: exeVer, test_version: "6.1.7600.16617" )){
				report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.1.7600.16617", install_path: sysPath );
				security_message( port: 0, data: report );
			}
		}
	}
}

