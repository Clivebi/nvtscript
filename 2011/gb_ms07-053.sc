if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801723" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-01-18 10:00:48 +0100 (Tue, 18 Jan 2011)" );
	script_cve_id( "CVE-2007-3036" );
	script_bugtraq_id( 25620 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Vulnerability in Windows Services for UNIX Could Allow Elevation of Privilege (939778)" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2007/Sep/1018678.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-053" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code with
  escalated privileges by running a specially crafted setuid binary." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 2 and prior

  - Microsoft Windows 2000 ervice Pack 4 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista" );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in Windows Services for UNIX
  and the Subsystem for UNIX-based Applications component when handling connection
  credentials for setuid binaries." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS07-053." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "939778" ) == 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(sysPath){
	exeVer = fetch_file_version( sysPath: sysPath, file_name: "posix.exe" );
	if(exeVer){
		if( hotfix_check_sp( win2k: 5, xp: 4 ) > 0 ){
			if(version_in_range( version: exeVer, test_version: "7.0", test_version2: "7.0.1701.45" ) || version_in_range( version: exeVer, test_version: "8.0", test_version2: "8.0.1969.57" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		else {
			if(hotfix_check_sp( win2003: 3 ) > 0){
				SP = get_kb_item( "SMB/Win2003/ServicePack" );
				if(ContainsString( SP, "Service Pack 1" )){
					if(version_in_range( version: exeVer, test_version: "7.0", test_version2: "7.0.1701.45" ) || version_in_range( version: exeVer, test_version: "8.0", test_version2: "8.0.1969.57" ) || version_in_range( version: exeVer, test_version: "9.0", test_version2: "9.0.3790.2982" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_in_range( version: exeVer, test_version: "7.0", test_version2: "7.0.1701.45" ) || version_in_range( version: exeVer, test_version: "8.0", test_version2: "8.0.1969.57" ) || version_in_range( version: exeVer, test_version: "9.0", test_version2: "9.0.3790.4124" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
		}
	}
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", item: "PathName" );
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "posix.exe" );
if(!exeVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3 ) > 0){
	if(version_is_less( version: exeVer, test_version: "6.0.6000.16543" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}

