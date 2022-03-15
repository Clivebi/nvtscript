if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901304" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-4774" );
	script_bugtraq_id( 56443 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-12-12 09:40:29 +0530 (Wed, 12 Dec 2012)" );
	script_name( "Microsoft Windows File Handling Component Remote Code Execution Vulnerability (2758857)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2758857" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-081" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_smb_windows_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attacker to gain the same user rights as
  the current user by execute arbitrary code with system-level privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to error in the File Handling component, which allow user
  browses to a folder that contains a file or sub folder names and can be
  exploited to corrupt memory via a file with a specially crafted filename." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-081." );
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
kernelPath = smb_get_systemroot();
if(!kernelPath){
	exit( 0 );
}
kernelVer = fetch_file_version( sysPath: kernelPath, file_name: "system32\\Kernel32.dll" );
if(!kernelVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: kernelVer, test_version: "5.1.2600.6293" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0 ){
		if(version_is_less( version: kernelVer, test_version: "5.2.3790.5069" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: kernelVer, test_version: "6.0.6002.18704" ) || version_in_range( version: kernelVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22941" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: kernelVer, test_version: "6.1.7600.17135" ) || version_in_range( version: kernelVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21334" ) || version_in_range( version: kernelVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17964" ) || version_in_range( version: kernelVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.22124" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

