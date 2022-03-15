if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902944" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-1278", "CVE-2013-1279", "CVE-2013-1280" );
	script_bugtraq_id( 57855, 57856, 57854 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-02-13 07:04:12 +0530 (Wed, 13 Feb 2013)" );
	script_name( "Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2799494)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2799494" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028126" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code with kernel-mode privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "insight", value: "- Race condition errors when handling certain objects in memory can be
    exploited to execute arbitrary code with kernel privileges.

  - An error when handling the reference counter for certain objects in memory
    can be exploited to execute arbitrary code with kernel privileges." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-017." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\ntoskrnl.exe" );
if(!exeVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: exeVer, test_version: "5.1.2600.6335" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0 ){
		if(version_is_less( version: exeVer, test_version: "5.2.3790.5107" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: exeVer, test_version: "6.0.6002.18765" ) || version_in_range( version: exeVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.23024" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: exeVer, test_version: "6.1.7600.17207" ) || version_in_range( version: exeVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21416" ) || version_in_range( version: exeVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.18043" ) || version_in_range( version: exeVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.22209" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

