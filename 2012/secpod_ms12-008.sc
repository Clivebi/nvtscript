if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902810" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0154", "CVE-2011-5046" );
	script_bugtraq_id( 51122, 51920 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-15 09:09:09 +0530 (Wed, 15 Feb 2012)" );
	script_name( "Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2660465)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2660465" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/71873" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18275" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-008" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a denial of
  service and possibly execute arbitrary code with kernel-level privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An error in win32k.sys when validating input passed from user mode through
    the kernel component of GDI can be exploited to corrupt memory via a
    specially crafted web page containing an IFRAME with an overly large
    'height' attribute viewed using the Apple Safari browser.

  - A use-after-free error in win32k.sys when handling certain keyboard layouts
    can be exploited to dereference already freed memory and gain escalated
    privileges." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-008." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2660465" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Win32k.sys" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "5.1.2600.6188" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win2003: 3 ) > 0 ){
		if(version_is_less( version: sysVer, test_version: "5.2.3790.4953" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18569" ) || version_in_range( version: sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22776" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(version_is_less( version: sysVer, test_version: "6.1.7600.16948" ) || version_in_range( version: sysVer, test_version: "6.1.7600.20000", test_version2: "6.1.7600.21126" ) || version_in_range( version: sysVer, test_version: "6.1.7601.17000", test_version2: "6.1.7601.17761" ) || version_in_range( version: sysVer, test_version: "6.1.7601.21000", test_version2: "6.1.7601.21897" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

