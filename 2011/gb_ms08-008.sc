if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801703" );
	script_version( "2020-01-07T09:06:32+0000" );
	script_tag( name: "last_modification", value: "2020-01-07 09:06:32 +0000 (Tue, 07 Jan 2020)" );
	script_tag( name: "creation_date", value: "2011-01-13 17:08:42 +0100 (Thu, 13 Jan 2011)" );
	script_cve_id( "CVE-2007-0065" );
	script_bugtraq_id( 27661 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Vulnerability in OLE Automation Could Allow Remote Code Execution (947890)" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2008/Feb/1019373.html" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-008" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2000 Service Pack 4 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista

  - Microsoft Visual Basic 6.0 Service Pack 6" );
	script_tag( name: "insight", value: "The flaw is due to an error in the VBScript and JScript scripting
  engines during handling of certain script requests when using OLE." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-008." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
dllPath = sysPath + "\\system32\\oleaut32.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if(hotfix_missing( name: "947890" ) == 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( item: "DisplayName", key: key + item );
	if(ContainsString( appName, "Microsoft Visual Basic" )){
		if(version_in_range( version: dllVer, test_version: "2.40", test_version2: "2.40.4531.9" ) || version_in_range( version: dllVer, test_version: "2.40", test_version2: "2.40.4519.9" ) || version_in_range( version: dllVer, test_version: "5.2", test_version2: "5.2.3790.726" ) || version_in_range( version: dllVer, test_version: "5.2", test_version2: "5.2.3790.3056" ) || version_in_range( version: dllVer, test_version: "5.2", test_version2: "5.2.3790.4201" ) || version_in_range( version: dllVer, test_version: "6.0", test_version2: "6.0.6000.20731" ) || version_in_range( version: dllVer, test_version: "3.50", test_version2: "3.50.5021.9" ) || version_in_range( version: dllVer, test_version: "5.1", test_version2: "5.1.2600.3265" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, winVista: 2 ) <= 0){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "2.40.4532.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "5.1.2600.3266" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
	}
	else {
		if( hotfix_check_sp( win2003: 3 ) > 0 ){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_is_less( version: dllVer, test_version: "5.2.3790.3057" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_is_less( version: dllVer, test_version: "5.2.3790.4202" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( winVista: 3 ) > 0){
				if(version_is_less( version: dllVer, test_version: "6.0.6000.16607" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
		}
	}
}

