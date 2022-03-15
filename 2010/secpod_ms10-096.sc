if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901169" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)" );
	script_bugtraq_id( 42648 );
	script_cve_id( "CVE-2010-3147" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows Address Book Remote Code Execution Vulnerability (2423089)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2423089" );
	script_xref( name: "URL", value: "http://www.attackvector.org/new-dll-hijacking-exploits-many/" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-096" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "The Address Book (wab.exe) application insecurely loads certain libraries
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a vCard file from a network
  share." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-096." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win7: 1, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2423089" ) == 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "ProgramFilesDir" );
if(!sysPath){
	exit( 0 );
}
appPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wab.exe", item: "Path" );
if(!appPath){
	exit( 0 );
}
appPath = ereg_replace( pattern: "%.*%(.*)", replace: "\\1", string: appPath );
wabPath = sysPath + appPath + "\\wab.exe";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: wabPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: wabPath );
wabVer = GetVer( file: file, share: share );
if(!wabVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(( ContainsString( SP, "Service Pack 3" ) )){
		if(version_is_less( version: wabVer, test_version: "6.0.2900.6040" )){
			report = report_fixed_ver( installed_version: wabVer, fixed_version: "6.0.2900.6040", install_path: wabPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2003: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: wabVer, test_version: "6.0.3790.4785" )){
				report = report_fixed_ver( installed_version: wabVer, fixed_version: "6.0.3790.4785", install_path: wabPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(!SP){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
	}
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: wabVer, test_version: "6.0.6001.18535" )){
			report = report_fixed_ver( installed_version: wabVer, fixed_version: "6.0.6001.18535", install_path: wabPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: wabVer, test_version: "6.0.6002.18324" )){
			report = report_fixed_ver( installed_version: wabVer, fixed_version: "6.0.6002.18324", install_path: wabPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win7: 1 ) > 0){
		if(version_is_less( version: wabVer, test_version: "6.1.7600.16684" )){
			report = report_fixed_ver( installed_version: wabVer, fixed_version: "6.1.7600.16684", install_path: wabPath );
			security_message( port: 0, data: report );
		}
	}
}

