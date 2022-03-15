if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900065" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4841", "CVE-2009-0087", "CVE-2009-0088", "CVE-2009-0235" );
	script_bugtraq_id( 29769 );
	script_name( "WordPad and Office Text Converter Memory Corruption Vulnerability (960477)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx/kb/960477" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-010" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_ms_office_detection_900025.sc", "secpod_office_products_version_900032.sc" );
	script_mandatory_keys( "SMB/Office/Word/Version" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker craft malicious arbitrary codes
  into the files and can trick the user to open those crafted documents which
  may lead to remote arbitrary code execution inside the context of the affected system." );
	script_tag( name: "affected", value: "WordPad on MS Windows 2K/XP/2K3

  MS Office 2000 Word Service Pack 3

  MS Office XP Word Service Pack 3

  MS Office Converters Pack" );
	script_tag( name: "insight", value: "- Input validation error when parsing document files i.e. Office files, RTF,
  Wordperfect files or Write files." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to Microsoft
  Bulletin MS09-010." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("http_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Shared Tools", item: "SharedFilesDir" );
if(!dllPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath + "TextConv\\MSCONV97.DLL" );
dllVer = GetVer( file: file, share: share );
officeVer = get_kb_item( "MS/Office/Ver" );
wordVer = get_kb_item( "SMB/Office/Word/Version" );
if(wordVer && IsMatchRegexp( wordVer, "^(9|10)\\." ) && officeVer && IsMatchRegexp( officeVer, "^(9|10)\\." )){
	if(dllVer){
		if(hotfix_missing( name: "921606" ) == 1 || hotfix_missing( name: "933399" ) == 1){
			if(version_is_less( version: dllVer, test_version: "2003.1100.8202.0" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\WORDPAD.EXE" )){
	key = "SOFTWARE\\Microsoft\\Shared Tools\\MSWord8\\Clients";
	if(registry_key_exists( key: key )){
		for item in registry_enum_values( key: key ) {
			if(ContainsString( item, "wordpad" )){
				if(hotfix_missing( name: "923561" ) == 1){
					share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: item );
					file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: item );
					wpVer = GetVer( file: file, share: share );
					if(wpVer != NULL){
						if( hotfix_check_sp( win2k: 5 ) > 0 ){
							if(version_is_less( version: wpVer, test_version: "5.0.2195.7155" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
							}
						}
						else {
							if( hotfix_check_sp( xp: 4 ) > 0 ){
								SP = get_kb_item( "SMB/WinXP/ServicePack" );
								if( ContainsString( SP, "Service Pack 2" ) ){
									if(version_is_less( version: wpVer, test_version: "5.1.2600.3355" )){
										security_message( port: 0, data: "The target host was found to be vulnerable" );
									}
								}
								else {
									if(ContainsString( SP, "Service Pack 3" )){
										if(version_is_less( version: wpVer, test_version: "5.1.2600.5584" )){
											security_message( port: 0, data: "The target host was found to be vulnerable" );
										}
									}
								}
							}
							else {
								if(hotfix_check_sp( win2003: 3 ) > 0){
									SP = get_kb_item( "SMB/Win2003/ServicePack" );
									if( ContainsString( SP, "Service Pack 1" ) ){
										if(version_is_less( version: wpVer, test_version: "5.2.3790.3129" )){
											security_message( port: 0, data: "The target host was found to be vulnerable" );
										}
									}
									else {
										if(ContainsString( SP, "Service Pack 2" )){
											if(version_is_less( version: wpVer, test_version: "5.2.3790.4282" )){
												security_message( port: 0, data: "The target host was found to be vulnerable" );
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	convName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( convName, "Microsoft Office Converter" )){
		if(!dllVer){
			exit( 0 );
		}
		if(hotfix_missing( name: "960476" ) == 0){
			exit( 0 );
		}
		if(version_is_less( version: dllVer, test_version: "2003.1100.8202.0" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}

