if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900240" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)" );
	script_bugtraq_id( 39308, 39381 );
	script_cve_id( "CVE-2010-0024", "CVE-2010-0025" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Microsoft Exchange and Windows SMTP Service Denial of Service Vulnerability (981832)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-024" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could lead to Denial of Service." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Exchange Server 2000 Service Pack 3

  - Microsoft Exchange Server 2003 Service Pack 2" );
	script_tag( name: "insight", value: "An error exists MS Windows Simple Mail Transfer Protocol (SMTP) component,

  - while handling specially crafted DNS Mail Exchanger (MX) resource records.

  - due to the manner in which the SMTP component handles memory allocation" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-024." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3 ) <= 0){
	exit( 0 );
}
smtpPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\InetStp", item: "InstallPath" );
if(smtpPath){
	if(hotfix_missing( name: "976323" ) == 1){
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: smtpPath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: smtpPath + "\\smtpsvc.dll" );
		exeVer = GetVer( file: file, share: share );
		if(exeVer){
			if( hotfix_check_sp( win2k: 5 ) > 0 ){
				if(version_is_less( version: exeVer, test_version: "5.0.2195.7381" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			else {
				if( hotfix_check_sp( xp: 4 ) > 0 ){
					SP = get_kb_item( "SMB/WinXP/ServicePack" );
					if( ContainsString( SP, "Service Pack 2" ) ){
						if(version_is_less( version: exeVer, test_version: "6.0.2600.3680" )){
							security_message( port: 0, data: "The target host was found to be vulnerable" );
							exit( 0 );
						}
					}
					else {
						if(ContainsString( SP, "Service Pack 3" )){
							if(version_is_less( version: exeVer, test_version: "6.0.2600.5949" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
					}
				}
				else {
					if(hotfix_check_sp( win2003: 3 ) > 0){
						SP = get_kb_item( "SMB/Win2003/ServicePack" );
						if(ContainsString( SP, "Service Pack 2" )){
							if(version_is_less( version: exeVer, test_version: "6.0.3790.4675" )){
								security_message( port: 0, data: "The target host was found to be vulnerable" );
								exit( 0 );
							}
						}
					}
				}
			}
		}
	}
}
exchangePath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Exchange\\Setup", item: "Services" );
if(exchangePath){
	if(hotfix_missing( name: "976703" ) == 0 || hotfix_missing( name: "976702" ) == 0){
		exit( 0 );
	}
	common_exspmsg_file = TRUE;
	exePath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
	if(!exePath){
		exit( 0 );
	}
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exePath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exePath + "\\exspmsg.dll" );
	fileVersion = GetVer( file: file, share: share );
	if(!fileVersion){
		common_exspmsg_file = FALSE;
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: exchangePath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: exchangePath + "\\bin\\Msgfilter.dll" );
		fileVersion = GetVer( file: file, share: share );
	}
	if(!fileVersion){
		exit( 0 );
	}
	if( common_exspmsg_file ){
		if(version_in_range( version: fileVersion, test_version: "6.5", test_version2: "6.5.7233.40" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
	else {
		if(version_in_range( version: fileVersion, test_version: "6.5", test_version2: "6.5.7656.1" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

