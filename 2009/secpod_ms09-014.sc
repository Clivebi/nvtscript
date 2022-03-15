if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900328" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-15 18:21:29 +0200 (Wed, 15 Apr 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-2540", "CVE-2009-0550", "CVE-2009-0551", "CVE-2009-0552", "CVE-2009-0553", "CVE-2009-0554" );
	script_bugtraq_id( 29445, 34439, 34438, 34423, 34424, 34426 );
	script_name( "Microsoft Internet Explorer Remote Code Execution Vulnerability (963027)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes into
  the context of the affected system and can cause denial of service in the
  affected system." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 5.x/6.x/7.x." );
	script_tag( name: "insight", value: "Flaws are due to

  - Blended threat issue which allows executables to be downloaded in user's
    computer without prompting.

  - Vulnerability in NT LAN Manager which allows the attacker to replay NTLM
    credentials.

  - Arbitrary code execution in Internet Explorer at run time of Internet
    Explorer Browser.

  - Internet Explorer Uninitialized Memory Variant which lets the attacker
    cause remote code execution." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-014." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/963027" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-014" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 2, win2008: 2 ) <= 0){
	exit( 0 );
}
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(hotfix_missing( name: "963027" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	vers = fetch_file_version( sysPath: sysPath, file_name: "mshtml.dll" );
	if(vers){
		if( hotfix_check_sp( win2k: 5 ) > 0 ){
			if(version_in_range( version: vers, test_version: "5.0", test_version2: "5.0.3874.1899" ) || version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2800.1624" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		else {
			if( hotfix_check_sp( xp: 4 ) > 0 ){
				SP = get_kb_item( "SMB/WinXP/ServicePack" );
				if( ContainsString( SP, "Service Pack 2" ) ){
					if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2900.3526" ) || version_in_range( version: vers, test_version: "7.0.0000.00000", test_version2: "7.0.6000.16824" ) || version_in_range( version: vers, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21014" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				else {
					if(ContainsString( SP, "Service Pack 3" )){
						if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.2900.5763" ) || version_in_range( version: vers, test_version: "7.0.0000.00000", test_version2: "7.0.6000.16824" ) || version_in_range( version: vers, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21014" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			else {
				if(hotfix_check_sp( win2003: 3 ) > 0){
					SP = get_kb_item( "SMB/Win2003/ServicePack" );
					if( ContainsString( SP, "Service Pack 1" ) ){
						if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3790.3303" ) || version_in_range( version: vers, test_version: "7.0.0000.00000", test_version2: "7.0.6000.16824" ) || version_in_range( version: vers, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21014" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
						}
						exit( 0 );
					}
					else {
						if(ContainsString( SP, "Service Pack 2" )){
							if(version_in_range( version: vers, test_version: "6.0", test_version2: "6.0.3790.4469" ) || version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.6000.16824" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
							}
							exit( 0 );
						}
					}
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "mshtml.dll" );
	if(dllVer){
		if(hotfix_check_sp( winVista: 2, win2008: 2 ) > 0){
			if(version_in_range( version: dllVer, test_version: "7.0.6000.16000", test_version2: "7.0.6000.16829" ) || version_in_range( version: dllVer, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21022" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(!SP){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
			}
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_in_range( version: dllVer, test_version: "7.0.6001.18000", test_version2: "7.0.6001.18225" ) || version_in_range( version: dllVer, test_version: "7.0.6001.22000", test_version2: "7.0.6001.22388" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
		}
	}
}

