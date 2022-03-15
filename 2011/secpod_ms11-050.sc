if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902443" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)" );
	script_cve_id( "CVE-2011-1246", "CVE-2011-1250", "CVE-2011-1251", "CVE-2011-1252", "CVE-2011-1254", "CVE-2011-1255", "CVE-2011-1256", "CVE-2011-1258", "CVE-2011-1260", "CVE-2011-1261", "CVE-2011-1262" );
	script_bugtraq_id( 48200, 48202, 48203, 48199, 48204, 48206, 48207, 48201, 48208, 48210, 48211 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (2530548)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2530548" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-050" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed exploit attempts will result
  in denial-of-service conditions." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x." );
	script_tag( name: "insight", value: "Multiple flaws are due to: the way Internet Explorer enforces the content
  settings supplied by the Web server, handles HTML sanitization using
  toStaticHTML, handles objects in memory, and handles script during certain
  processes." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-050." );
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
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(hotfix_missing( name: "2530548" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Mshtml.dll" );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_in_range( version: dllVer, test_version: "6.0.2900.0000", test_version2: "6.0.2900.6103" ) || version_in_range( version: dllVer, test_version: "7.0.0000.00000", test_version2: "7.0.6000.17097" ) || version_in_range( version: dllVer, test_version: "7.0.6000.21000", test_version2: "7.0.6000.21299" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.19087" ) || version_in_range( version: dllVer, test_version: "8.0.6001.23000", test_version2: "8.0.6001.23180" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if( hotfix_check_sp( win2003: 3 ) > 0 ){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_in_range( version: dllVer, test_version: "6.0.3790.0000", test_version2: "6.0.3790.4856" ) || version_in_range( version: dllVer, test_version: "7.0.0000.00000", test_version2: "7.0.6000.17097" ) || version_in_range( version: dllVer, test_version: "7.0.6000.21000", test_version2: "7.0.6000.21299" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.19087" ) || version_in_range( version: dllVer, test_version: "8.0.6001.23000", test_version2: "8.0.6001.23180" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(!SP){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
			}
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_in_range( version: dllVer, test_version: "7.0.6001.18000", test_version2: "7.0.6001.18638" ) || version_in_range( version: dllVer, test_version: "7.0.6001.22000", test_version2: "7.0.6001.22904" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.19087" ) || version_in_range( version: dllVer, test_version: "8.0.6001.23000", test_version2: "8.0.6001.23180" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16429" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20529" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_in_range( version: dllVer, test_version: "7.0.6002.18000", test_version2: "7.0.6002.18456" ) || version_in_range( version: dllVer, test_version: "7.0.6002.22000", test_version2: "7.0.6002.22628" ) || version_in_range( version: dllVer, test_version: "8.0.6001.18000", test_version2: "8.0.6001.19087" ) || version_in_range( version: dllVer, test_version: "8.0.6001.23000", test_version2: "8.0.6001.23180" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16429" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20529" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(version_in_range( version: dllVer, test_version: "8.0.7600.16000", test_version2: "8.0.7600.16820" ) || version_in_range( version: dllVer, test_version: "8.0.7600.20000", test_version2: "8.0.7600.20974" ) || version_in_range( version: dllVer, test_version: "8.0.7601.16000", test_version2: "8.0.7601.17621" ) || version_in_range( version: dllVer, test_version: "8.0.7601.21000", test_version2: "8.0.7601.21734" ) || version_in_range( version: dllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16429" ) || version_in_range( version: dllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20529" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

