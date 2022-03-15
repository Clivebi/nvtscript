if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900873" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 35255 );
	script_name( "Microsoft Windows DNS Devolution Third-Level Domain Name Resolving Weakness (971888)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/957579" );
	script_xref( name: "URL", value: "http://www.microsoft.com/technet/security/advisory/971888.mspx" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful attacks may result in disclosure of the private IP address and
  authentication credentials, modification of client proxy settings, phishing,
  redirection to other malicious sites, enticing vulnerable users to download
  malware." );
	script_tag( name: "affected", value: "- Microsoft Windows 2k  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2k3 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to design error in the DNS devolution process which can
  be exploited by setting up a malicious site and carry out attacks against
  victims who are inadvertently directed to the malicious site." );
	script_tag( name: "solution", value: "Apply the Security update" );
	script_tag( name: "summary", value: "This host has Microsoft DNS Devolution and is prone to Third-Level
  Domain Name Resolving Weakness." );
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
if(hotfix_missing( name: "957579" ) == 0){
	exit( 0 );
}
dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!dllPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath + "\\dnsapi.dll" );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "5.0.2195.7280" )){
		report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.0.2195.7280" );
		security_message( port: 0, data: report );
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: dllVer, test_version: "5.1.2600.3557" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.3557" );
				security_message( port: 0, data: report );
			}
		}
		else {
			if( ContainsString( SP, "Service Pack 3" ) ){
				if(version_is_less( version: dllVer, test_version: "5.1.2600.5797" )){
					report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.5797" );
					security_message( port: 0, data: report );
				}
			}
			else {
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
	else {
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 2" ) ){
				if(version_is_less( version: dllVer, test_version: "5.2.3790.4498" )){
					report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.2.3790.4498" );
					security_message( port: 0, data: report );
				}
			}
			else {
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

