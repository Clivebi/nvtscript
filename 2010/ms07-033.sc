if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.102057" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)" );
	script_bugtraq_id( 24418, 24423, 24372, 24429, 24426, 22966 );
	script_cve_id( "CVE-2007-1751", "CVE-2007-1750", "CVE-2007-0218", "CVE-2007-3027", "CVE-2007-2222", "CVE-2007-1499" );
	script_name( "Cumulative Security Update for Internet Explorer (933566)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/471210/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-07-038.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-033" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 LSS" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Microsoft Internet Explorer 5.01, 6, and 7 allows remote attackers
  to execute arbitrary code by causing Internet Explorer to access an
  uninitialized or deleted object, related to prototype variables and
  table cells, aka Uninitialized Memory Corruption Vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, vista: 2 ) <= 0){
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(hotfix_missing( name: "933566" ) == 0){
	exit( 0 );
}
dllPath = registry_get_sz( item: "Install Path", key: "SOFTWARE\\Microsoft\\COM3\\Setup" );
dllPath += "\\mshtml.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath );
vers = GetVer( file: file, share: share );
if(!vers){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	SP = get_kb_item( "SMB/Win2K/ServicePack" );
	if(ContainsString( SP, "Service Pack 4" )){
		if(version_in_range( version: vers, test_version: "5.01", test_version2: "5.0.3853.3000" ) || version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2800.1595" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2900.3132" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.6000.16481" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
	else {
		if( hotfix_check_sp( win2003: 3 ) > 0 ){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3790.2920" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.6000.16481" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			else {
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3790.4064" ) || version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3790.2920" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.6000.16481" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
			}
		}
		else {
			if(hotfix_check_sp( vista: 2 ) > 0){
				SP = get_kb_item( "SMB/WinVista/ServicePack" );
				if(ContainsString( SP, "Service Pack 0" )){
					if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.6000.16481" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
			}
		}
	}
}
exit( 99 );

