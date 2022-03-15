if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902807" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 51292, 51295 );
	script_cve_id( "CVE-2012-0003", "CVE-2012-0004" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-01-11 10:10:10 +0530 (Wed, 11 Jan 2012)" );
	script_name( "Microsoft Windows Media Could Allow Remote Code Execution Vulnerabilities (2636391)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026492" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/47485" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-004" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application which can compromise the
  application and possibly the computer." );
	script_tag( name: "affected", value: "- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior

  - Microsoft Windows Media Center TV Pack for Microsoft Windows Vista" );
	script_tag( name: "insight", value: "- An unspecified error in the Windows multimedia library (winmm.dll) when
    parsing MIDI files can be exploited via a specially crafted file opened
    in Windows Media Player.

  - An unspecified error exists in the Line21 DirectShow filter (Quartz.dll
    and Qdvd.dll) when parsing specially crafted media files." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-004." );
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
if(hotfix_missing( name: "2598479" ) == 0 && hotfix_missing( name: "2631813" ) == 0){
	exit( 0 );
}
winName = get_kb_item( "SMB/WindowsName" );
if(ContainsString( winName, "Windows Vista" )){
	mediaTVPackVer = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\Current" + "Version\\Media Center", item: "Ident" );
	if(hotfix_missing( name: "2628642" ) == 0){
		exit( 0 );
	}
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
mciseqVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Mciseq.dll" );
quartzVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Quartz.dll" );
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 3" )){
		if(( mciseqVer && version_is_less( version: mciseqVer, test_version: "5.1.2600.6160" ) ) || ( quartzVer && version_is_less( version: quartzVer, test_version: "6.5.2600.6169" ) )){
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
			if(( mciseqVer && version_is_less( version: mciseqVer, test_version: "5.2.3790.4916" ) ) || ( quartzVer && version_is_less( version: quartzVer, test_version: "6.5.3790.4928" ) )){
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
			if(mediaTVPackVer && ( ContainsString( mediaTVPackVer, "5.1" ) )){
				mstvVer = fetch_file_version( sysPath: sysPath, file_name: "ehome\\Mstvcapn.dll" );
				if(mstvVer && version_is_less( version: mstvVer, test_version: "6.1.1000.18311" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(ContainsString( SP, "Service Pack 2" )){
				if(( mciseqVer && ( version_in_range( version: mciseqVer, test_version: "6.0.6002.18000", test_version2: "6.0.6002.18527" ) || version_in_range( version: mciseqVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.22725" ) ) ) || ( quartzVer && ( version_in_range( version: quartzVer, test_version: "6.0.6002.18000", test_version2: "6.6.6002.18532" ) || version_in_range( version: quartzVer, test_version: "6.6.6002.22000", test_version2: "6.6.6002.22731" ) ) )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(quartzVer && ( version_is_less( version: quartzVer, test_version: "6.6.7600.16905" ) || version_in_range( version: quartzVer, test_version: "6.6.7600.21000", test_version2: "6.6.7600.21076" ) || version_in_range( version: quartzVer, test_version: "6.6.7601.17000", test_version2: "6.6.7601.17712" ) || version_in_range( version: quartzVer, test_version: "6.6.7601.21000", test_version2: "6.6.7601.21846" ) )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
			}
		}
	}
}

