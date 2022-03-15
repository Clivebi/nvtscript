if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900874" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2521", "CVE-2009-3023" );
	script_bugtraq_id( 36273, 36189 );
	script_name( "Microsoft IIS FTP Service Remote Code Execution Vulnerabilities (975254)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/975254" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2542" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2481" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-053" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code with
  SYSTEM privileges which may result Denial of Service on the affected server." );
	script_tag( name: "affected", value: "Microsoft Internet Information Services (IIS) 5.0/5/1/6.0." );
	script_tag( name: "insight", value: "- This issue is caused by an error when processing directory listing commands
  including the '*' character and '../' sequences, which could be exploited to exhaust the stack.

  - An heap-based buffer overflow error occurs in the FTP service when processing
  a specially crafted 'NLST' command." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-053." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "975254" ) == 0 )){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\inetsrv\\ftpsvc2.dll" );
if(!dllVer){
	exit( 0 );
}
if(hotfix_check_sp( win2k: 5 ) > 0){
	if(version_is_less( version: dllVer, test_version: "5.0.2195.7336" )){
		security_message( 21 );
		exit( 0 );
	}
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if( ContainsString( SP, "Service Pack 2" ) ){
		if(version_is_less( version: dllVer, test_version: "6.0.2600.3624" )){
			security_message( 21 );
		}
		exit( 0 );
	}
	else {
		if(ContainsString( SP, "Service Pack 3" )){
			if(version_is_less( version: dllVer, test_version: "6.0.2600.5875" )){
				security_message( 21 );
			}
			exit( 0 );
		}
	}
	security_message( 21 );
}
else {
	if( hotfix_check_sp( win2003: 3 ) > 0 ){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "6.0.3790.4584" )){
				security_message( 21 );
			}
			exit( 0 );
		}
		security_message( 21 );
	}
	else {
		if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
			if(version_in_range( version: dllVer, test_version: "7.0.6000.16000", test_version2: "7.0.6000.16922" ) || version_in_range( version: dllVer, test_version: "7.0.6000.20000", test_version2: "7.0.6000.21122" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(!SP){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
			}
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_in_range( version: dllVer, test_version: "7.0.6001.18000", test_version2: "7.0.6001.18326" ) || version_in_range( version: dllVer, test_version: "7.0.6001.22000", test_version2: "7.0.6001.22515" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_in_range( version: dllVer, test_version: "7.0.6002.18000", test_version2: "7.0.6002.18106" ) || version_in_range( version: dllVer, test_version: "7.0.6002.22000", test_version2: "7.0.6002.22218" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

