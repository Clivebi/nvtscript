if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902978" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-1300", "CVE-2013-1340", "CVE-2013-1345", "CVE-2013-3129", "CVE-2013-3167", "CVE-2013-3172", "CVE-2013-3173", "CVE-2013-3660" );
	script_bugtraq_id( 60946, 60947, 60948, 60978, 60949, 60951, 60950, 60051 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-07-10 08:46:58 +0530 (Wed, 10 Jul 2013)" );
	script_name( "MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2850851)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2850851" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028746" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-053" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a buffer
  overflow and execute arbitrary code with kernel privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Unspecified errors within the Windows kernel-mode driver (win32k.sys) when
    processing certain objects and can be exploited to cause a crash or execute
    arbitrary code with the kernel privilege.

  - An error exists within the GDI+ subsystem." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS13-053." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
Win32sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Win32k.sys" );
if(!Win32sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: Win32sysVer, test_version: "5.1.2600.6404" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3, xpx64: 3, win2003x64: 3 ) > 0 ){
		if(version_is_less( version: Win32sysVer, test_version: "5.2.3790.5174" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: Win32sysVer, test_version: "6.0.6002.18861" ) || version_in_range( version: Win32sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.23131" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
				if(version_is_less( version: Win32sysVer, test_version: "6.1.7601.18176" ) || version_in_range( version: Win32sysVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22347" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
					if(version_is_less( version: Win32sysVer, test_version: "6.2.9200.16627" ) || version_in_range( version: Win32sysVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.20731" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
		}
	}
}

