if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900566" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-11 17:12:55 +0200 (Thu, 11 Jun 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1138", "CVE-2009-1139" );
	script_bugtraq_id( 35226, 35225 );
	script_name( "Microsoft Active Directory LDAP Remote Code Execution Vulnerability (969805)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/971055" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-018" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Remote attackers could execute arbitrary code on the affected system thus
  taking complete control of that system and may cause denial of service." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to

  - Incorrect freeing of memory when processing specially crafted LDAP or
  LDAPS requests.

  - Improperly memory management while executing LDAP or LDAPS requests
  that contain specific OID filters." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-018." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "969805" ) == 1 ) && registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\NTDS\\Performance" )){
	dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
	if(dllPath != NULL){
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
		ntdsaFile = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath + "\\Ntdsa.dll" );
		ntdsaVer = GetVer( file: ntdsaFile, share: share );
		if(ntdsaVer != NULL){
			if( hotfix_check_sp( win2k: 5 ) > 0 ){
				if(version_is_less( version: ntdsaVer, test_version: "5.0.2195.7292" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			else {
				if(hotfix_check_sp( win2003: 3 ) > 0){
					SP = get_kb_item( "SMB/Win2003/ServicePack" );
					if(ContainsString( SP, "Service Pack 2" )){
						if(version_is_less( version: ntdsaVer, test_version: "5.2.3790.4501" )){
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
if(( hotfix_missing( name: "970437" ) == 1 ) && registry_key_exists( key: "SYSTEM\\CurrentControlSet\\Services\\ADAM\\Linkage" )){
	dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
	if(dllPath != NULL){
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
		adamdsaFile = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath - "system32" + "ADAM\\Adamdsa.dll" );
		adamdsaVer = GetVer( file: adamdsaFile, share: share );
		if(adamdsaVer != NULL){
			if( hotfix_check_sp( xp: 4 ) > 0 ){
				SP = get_kb_item( "SMB/WinXP/ServicePack" );
				if(IsMatchRegexp( SP, "Service Pack (2|3)" )){
					if(version_is_less( version: adamdsaVer, test_version: "1.1.3790.4501" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			else {
				if(hotfix_check_sp( win2003: 3 ) > 0){
					SP = get_kb_item( "SMB/Win2003/ServicePack" );
					if(ContainsString( SP, "Service Pack 2" )){
						if(version_is_less( version: adamdsaVer, test_version: "1.1.3790.4503" )){
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

