if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901041" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-14 18:36:58 +0200 (Wed, 14 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1547", "CVE-2009-2529", "CVE-2009-2530", "CVE-2009-2531" );
	script_bugtraq_id( 36622, 36621, 36620, 36616 );
	script_name( "Microsoft Internet Explorer Multiple Code Execution Vulnerabilities (974455)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes via
  specially crafted HTML page in the context of the affected system and cause
  memory corruption." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 5.x/6.x/7.x/8.x." );
	script_tag( name: "insight", value: "These issues are caused by memory corruption errors when processing a specially
  crafted data stream header, when handling certain arguments, or when accessing
  certain objects." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-054." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/974455" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/976749" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2889" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-054" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3, win2008: 3, win7: 1 ) <= 0){
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(hotfix_missing( name: "974455" ) == 0){
	if(hotfix_missing( name: "976749" ) == 0){
		exit( 0 );
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	vers = fetch_file_version( sysPath: sysPath, file_name: "mshtml.dll" );
	if(vers){
		if( hotfix_check_sp( win2k: 5 ) > 0 ){
			if(version_in_range( version: vers, test_version: "5.0", test_version2: "5.0.3881.1899" ) || version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2800.1639" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
		else {
			if( hotfix_check_sp( xp: 4 ) > 0 ){
				SP = get_kb_item( "SMB/WinXP/ServicePack" );
				if( ContainsString( SP, "Service Pack 2" ) ){
					if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2900.3635" ) || version_in_range( version: vers, test_version: "7.0.0000.00000", test_version2: "7.0.6000.16938" ) || version_in_range( version: vers, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21141" ) || version_in_range( version: vers, test_version: "8.0.6000.16000", test_version2: "8.0.6001.18851" ) || version_in_range( version: vers, test_version: "8.0.6001.20000", test_version2: "8.0.6001.22941" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				else {
					if(ContainsString( SP, "Service Pack 3" )){
						if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2900.5889" ) || version_in_range( version: vers, test_version: "7.0.0000.00000", test_version2: "7.0.6000.16938" ) || version_in_range( version: vers, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21141" ) || version_in_range( version: vers, test_version: "8.0.6000.16000", test_version2: "8.0.6001.18851" ) || version_in_range( version: vers, test_version: "8.0.6001.20000", test_version2: "8.0.6001.22941" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			else {
				if(hotfix_check_sp( win2003: 3 ) > 0){
					SP = get_kb_item( "SMB/Win2003/ServicePack" );
					if(ContainsString( SP, "Service Pack 2" )){
						if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3790.4604" ) || version_in_range( version: vers, test_version: "7.0.0000.00000", test_version2: "7.0.6000.16938" ) || version_in_range( version: vers, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21141" ) || version_in_range( version: vers, test_version: "8.0.6000.16000", test_version2: "8.0.6001.18851" ) || version_in_range( version: vers, test_version: "8.0.6001.20000", test_version2: "8.0.6001.22941" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "mshtml.dll" );
if(!dllVer){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(version_in_range( version: dllVer, test_version: "7.0.6000.16000", test_version2: "7.0.6000.16915" ) || version_in_range( version: dllVer, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21115" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.18827" ) || version_in_range( version: dllVer, test_version: "8.0.6001.22000", test_version2: "8.0.6001.22917" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(!SP){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
	}
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_in_range( version: dllVer, test_version: "7.0.6001.16000", test_version2: "7.0.6001.18318" ) || version_in_range( version: dllVer, test_version: "7.0.6001.22000", test_version2: "7.0.6001.22507" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.18827" ) || version_in_range( version: dllVer, test_version: "8.0.6001.22000", test_version2: "8.0.6001.22917" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_in_range( version: dllVer, test_version: "7.0.6002.18000", test_version2: "7.0.6002.18099" ) || version_in_range( version: dllVer, test_version: "7.0.6002.22000", test_version2: "7.0.6002.22211" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.18827" ) || version_in_range( version: dllVer, test_version: "8.0.6001.22000", test_version2: "8.0.6001.22917" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}
if(hotfix_check_sp( win7: 1 ) > 0){
	if(version_in_range( version: dllVer, test_version: "8.0.7600.16000", test_version2: "8.0.7600.16418" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
