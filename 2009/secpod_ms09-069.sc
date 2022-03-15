if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901063" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-09 16:08:24 +0100 (Wed, 09 Dec 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-3675" );
	script_name( "Microsoft Windows LSASS Denial of Service Vulnerability (975467)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/974392" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3433" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-069" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a Denial of
  Service on the victim's system." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior" );
	script_tag( name: "insight", value: "This issue is caused by an error when communicating through Internet Protocol
  security (IPsec), sending a specially crafted ISAKMP message to the Local
  Security Authority Subsystem Service (LSASS) on an affected system." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-069." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-069" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "974392" ) == 0){
	exit( 0 );
}
dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
if(!dllPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath + "\\Oakley.dll" );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: dllVer, test_version: "5.0.2195.7343" )){
		report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.0.2195.7343" );
		security_message( port: 0, data: report );
	}
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: dllVer, test_version: "5.1.2600.3632" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.3632" );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: dllVer, test_version: "5.1.2600.5886" )){
					report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.1.2600.5886" );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if(ContainsString( SP, "Service Pack 2" )){
				if(version_is_less( version: dllVer, test_version: "5.2.3790.4600" )){
					report = report_fixed_ver( installed_version: dllVer, fixed_version: "5.2.3790.4600" );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

