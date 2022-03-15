if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802468" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-10-11 17:15:51 +0530 (Thu, 11 Oct 2012)" );
	script_name( "Compatibility Issues Affecting Signed Microsoft Binaries (2749655)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2749655" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2756872" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2012/2749655" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "This could cause compatibility issues between affected binaries and
  Microsoft Windows and This issue could adversely impact the ability to properly
  install and uninstall affected Microsoft components and security updates." );
	script_tag( name: "affected", value: "- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "insight", value: "Issue involving binaries that were signed with digital certificates generated
  by Microsoft without proper timestamp attributes. This issue is caused by a
  missing timestamp Enhanced Key Usage (EKU) extension during certificate
  generation and signing of Microsoft core components and software." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "The host is installed with Microsoft Windows operating system and
  its missing updates according to Microsoft Security Advisory (2749655)" );
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
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Wintrust.dll" );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "5.131.2600.6285" )){
		log_message( port: 0 );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0 ){
		if(version_is_less( version: dllVer, test_version: "5.131.3790.5060" )){
			log_message( port: 0 );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: dllVer, test_version: "6.0.6002.18686" ) || version_in_range( version: dllVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22919" )){
				log_message( port: 0 );
			}
			exit( 0 );
		}
		else {
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: dllVer, test_version: "6.1.7600.17115" ) || version_in_range( version: dllVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21312" ) || version_in_range( version: dllVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17939" ) || version_in_range( version: dllVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.22098" )){
					log_message( port: 0 );
				}
			}
		}
	}
}

