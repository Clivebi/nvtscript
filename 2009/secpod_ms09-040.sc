if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900908" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-13 19:09:22 +0200 (Thu, 13 Aug 2009)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1922" );
	script_bugtraq_id( 35969 );
	script_name( "Microsoft Windows Message Queuing Privilege Escalation Vulnerability (971032)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code with
  SYSTEM level privileges and completely compromise the affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 2 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior" );
	script_tag( name: "insight", value: "An error occurs while parsing malicious IOCTL requests sent to the Message Queuing
  service (MSMQ) because the input data is not adequately sanitised before being passed into the buffer." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-040." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/971032" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-040" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "971032" ) == 0){
	exit( 0 );
}
exePath = registry_get_sz( item: "Install Path", key: "SOFTWARE\\Microsoft\\COM3\\Setup" );
if(!exePath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath + "\\Mqsvc.exe" );
exeVer = GetVer( file: file, share: share );
if(!exeVer){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_in_range( version: exeVer, test_version: "5.0", test_version2: "5.0.0.807" )){
		report = report_fixed_ver( installed_version: exeVer, vulnerable_range: "5.0 - 5.0.0.807" );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( xp: 3 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: exeVer, test_version: "5.1", test_version2: "5.1.0.1110" )){
				report = report_fixed_ver( installed_version: exeVer, vulnerable_range: "5.1 - 5.1.0.1110" );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
	}
	else {
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_in_range( version: exeVer, test_version: "5.2", test_version2: "5.2.2007.4529" )){
					report = report_fixed_ver( installed_version: exeVer, vulnerable_range: "5.2 - 5.2.2007.4529" );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", item: "PathName" );
if(!sysPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysPath + "\\System32\\Mqsvc.exe" );
exeVer = GetVer( file: file, share: share );
if(exeVer){
	if(hotfix_check_sp( winVista: 3 ) > 0){
		if(version_is_less( version: exeVer, test_version: "6.0.6000.16871" )){
			report = report_fixed_ver( installed_version: exeVer, fixed_version: "6.0.6000.16871" );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
}

