if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900052" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_bugtraq_id( 31682 );
	script_cve_id( "CVE-2008-1446" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "Windows Internet Printing Service Allow Remote Code Execution Vulnerability (953155)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_iis_detect_win.sc" );
	script_mandatory_keys( "MS/IIS/Ver" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-062" );
	script_tag( name: "impact", value: "Successful exploitation result in execution of arbitrary code by
  tricking Web Server into visiting to a malicious IPP server via a specially
  crafted HTTP POST request." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows 2008 Server Service Pack 1 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow error within the IPP
  (Internet Printing Protocol) ISAPI extension for IIS when processing
  specially crafted IPP responses." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-062." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 2, win2008: 2 ) <= 0){
	exit( 0 );
}
iisVer = get_kb_item( "MS/IIS/Ver" );
if(!iisVer){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Win32spl.dll" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win2k: 5 ) > 0){
	if(version_is_less( version: sysVer, test_version: "5.0.2195.7188" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
if(hotfix_check_sp( xp: 4 ) > 0){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if( ContainsString( SP, "Service Pack 2" ) ){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.3435" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if(ContainsString( SP, "Service Pack 3" )){
			if(version_is_less( version: sysVer, test_version: "5.1.2600.5664" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
if(hotfix_check_sp( win2003: 3, win2003x64: 3, xpx64: 3 ) > 0){
	SP = get_kb_item( "SMB/Win2003/ServicePack" );
	if(!SP){
		SP = get_kb_item( "SMB/Win2003x64/ServicePack" );
	}
	if(!SP){
		SP = get_kb_item( "SMB/WinXPx64/ServicePack" );
	}
	if( ContainsString( SP, "Service Pack 1" ) ){
		if(version_is_less( version: sysVer, test_version: "5.2.3790.3208" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	else {
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "5.2.3790.4371" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
if(hotfix_check_sp( winVista: 2, win2008: 2 ) > 0){
	if(version_is_less( version: sysVer, test_version: "6.0.6000.16728" ) || version_in_range( version: sysVer, test_version: "6.0.6000.20000", test_version2: "6.0.6000.20892" ) || version_in_range( version: sysVer, test_version: "6.0.6001.18000", test_version2: "6.0.6001.18118" ) || version_in_range( version: sysVer, test_version: "6.0.6001.22000", test_version2: "6.0.6001.22240" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

