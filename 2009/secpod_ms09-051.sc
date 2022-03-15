if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901039" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-14 16:47:08 +0200 (Wed, 14 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0555", "CVE-2009-2525" );
	script_bugtraq_id( 36614, 36602 );
	script_name( "Vulnerabilities in Windows Media Runtime Could Allow Remote Code Execution (975682)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2887" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/alerts/2009/Oct/1023005.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-051" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges and can cause Denial of Service." );
	script_tag( name: "affected", value: "- Microsoft Windows 2k Service Pack 2 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2k3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Memory corruption error when processing specially crafted ASF files that
    make use of the Window Media Speech codec.

  - Error in Windows Media Runtime due to improper initialization of certain
    functions in compressed audio files." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-051." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "954155" ) == 0 ) || ( hotfix_missing( name: "975025" ) == 0 )){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "wmspdmod.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_in_range( version: dllVer, test_version: "9.0", test_version2: "9.0.0.3268" ) || version_in_range( version: dllVer, test_version: "10.0", test_version2: "10.0.0.4069" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" ) || ContainsString( SP, "Service Pack 3" )){
			if(version_in_range( version: dllVer, test_version: "9.0.0.3", test_version2: "9.0.0.3268" ) || version_in_range( version: dllVer, test_version: "9.0.0.4", test_version2: "9.0.0.4504" ) || version_in_range( version: dllVer, test_version: "10.0.0.3", test_version2: "10.0.0.3703" ) || version_in_range( version: dllVer, test_version: "10.0.0.40", test_version2: "10.0.0.4069" ) || version_in_range( version: dllVer, test_version: "10.0.0.43", test_version2: "10.0.0.4364" ) || version_in_range( version: dllVer, test_version: "11.0.0.0", test_version2: "11.0.5721.5262" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(( ContainsString( SP, "Service Pack 1" ) ) || ( ContainsString( SP, "Service Pack 2" ) )){
				if(version_in_range( version: dllVer, test_version: "10.0.0.3", test_version2: "10.0.0.3711" ) || version_in_range( version: dllVer, test_version: "10.0.0.4", test_version2: "10.0.0.4003" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "wmspdmod.dll" );
	if(!dllVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: dllVer, test_version: "11.0.6001.7005" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "11.0.6002.18034" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2008: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: dllVer, test_version: "11.0.6001.7005" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "11.0.6002.18034" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "msaud32.acm" );
if(dllVer){
	if(version_is_less( version: dllVer, test_version: "8.0.0.4502" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

