if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902984" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-3129" );
	script_bugtraq_id( 60978 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-07-10 15:54:12 +0530 (Wed, 10 Jul 2013)" );
	script_name( "Microsoft Windows Journal Remote Code Execution Vulnerabilities (2848295)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2835364" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1028750" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms13-054" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on use." );
	script_tag( name: "affected", value: "- Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error when processing TrueType fonts and can be
  exploited to cause a buffer overflow via a specially crafted file." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS13-054." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
if(!sysPath){
	exit( 0 );
}
sysPath = sysPath + "\\Microsoft Shared\\ink";
Win32sysVer = fetch_file_version( sysPath: sysPath, file_name: "Journal.dll" );
if(!Win32sysVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if(version_is_less( version: Win32sysVer, test_version: "6.0.6002.18817" ) || version_in_range( version: Win32sysVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.23093" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
		if(version_is_less( version: Win32sysVer, test_version: "6.1.7601.18126" ) || version_in_range( version: Win32sysVer, test_version: "6.1.7601.22000", test_version2: "6.1.7601.22295" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
			if(version_is_less( version: Win32sysVer, test_version: "6.2.9200.16581" ) || version_in_range( version: Win32sysVer, test_version: "6.2.9200.20000", test_version2: "6.2.9200.20684" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
	}
}

