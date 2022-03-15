if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800023" );
	script_version( "2020-06-09T11:16:08+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-2245" );
	script_bugtraq_id( 30594 );
	script_name( "Microsoft Windows Image Color Management System Code Execution Vulnerability (952954)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-046" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could execute arbitrary code when a user opens a
  specially crafted image file and can gain same user rights as the local user. An attacker could then:

  - install programs

  - view, change, or delete data

  - create new accounts." );
	script_tag( name: "affected", value: "Microsoft Windows 2K/XP/2003." );
	script_tag( name: "insight", value: "The flaw is due to the way Microsoft Color Management System (MSCMS)
  module of the Microsoft ICM component handles memory allocation." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-046." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
dllPath = sysPath + "\\Mscms.dll";
if(hotfix_missing( name: "952954" ) == 0){
	exit( 0 );
}
fileVer = get_version( dllPath: dllPath, string: "prod", offs: 60000 );
if(!fileVer){
	exit( 0 );
}
if( hotfix_check_sp( win2k: 5 ) > 0 ){
	if(version_is_less( version: fileVer, test_version: "5.0.2195.7162" )){
		report = report_fixed_ver( installed_version: fileVer, fixed_version: "5.0.2195.7162", install_path: dllPath );
		security_message( port: 0, data: report );
	}
	exit( 0 );
}
else {
	if( hotfix_check_sp( xp: 4 ) > 0 ){
		SP = get_kb_item( "SMB/WinXP/ServicePack" );
		if( ContainsString( SP, "Service Pack 2" ) ){
			if(version_is_less( version: fileVer, test_version: "5.1.2600.3396" )){
				report = report_fixed_ver( installed_version: fileVer, fixed_version: "5.1.2600.3396", install_path: dllPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		else {
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: fileVer, test_version: "5.1.2600.5627" )){
					report = report_fixed_ver( installed_version: fileVer, fixed_version: "5.1.2600.5627", install_path: dllPath );
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
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(version_is_less( version: fileVer, test_version: "5.2.3790.3163" )){
					report = report_fixed_ver( installed_version: fileVer, fixed_version: "5.2.3790.3163", install_path: dllPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_is_less( version: fileVer, test_version: "5.2.3790.4320" )){
						report = report_fixed_ver( installed_version: fileVer, fixed_version: "5.2.3790.4320", install_path: dllPath );
						security_message( port: 0, data: report );
					}
					exit( 0 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

