if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900051" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)" );
	script_bugtraq_id( 31651, 31652, 31653 );
	script_cve_id( "CVE-2008-2250", "CVE-2008-2251", "CVE-2008-2252" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_name( "Windows Kernel Elevation of Privilege Vulnerability (954211)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-061" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful local exploitation could result in denial of service
  condition due to memory corruption and can execute arbitrary code with
  elevated privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 2K Service Pack 4 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows 2008 Server Service Pack 1 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - an error within the processing of window properties passed from
    a parent to a child window when a new window is created.

  - an error while processing unspecified user mode input.

  - a double-free error within the handling of system calls from multiple
    threads." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-061." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3, win2008: 2, winVista: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "954211" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Win32k.sys" );
	if(sysVer){
		if(hotfix_check_sp( win2k: 5 ) > 0){
			if(egrep( pattern: "^5\\.0\\.2195\\.([0-6]?[0-9]?[0-9]?[0-9]|7(0[0-9][0-9]|" + "1[0-8][0-9]|19[0-3]))$", string: sysVer )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
			exit( 0 );
		}
		if(hotfix_check_sp( xp: 4 ) > 0){
			SP = get_kb_item( "SMB/WinXP/ServicePack" );
			if( ContainsString( SP, "Service Pack 2" ) ){
				if(egrep( pattern: "^5\\.1\\.2600\\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-3][0-9][0-9]|" + "4([0-3][0-9]|4[0-5])))$", string: sysVer )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 3" )){
					if(egrep( pattern: "^5\\.1\\.2600\\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9][0-9]|" + "6([0-6][0-9]|7[0-5])))$", string: sysVer )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		if(hotfix_check_sp( win2003: 3 ) > 0){
			SP = get_kb_item( "SMB/Win2003/ServicePack" );
			if( ContainsString( SP, "Service Pack 1" ) ){
				if(egrep( pattern: "^5\\.2\\.3790\\.([0-2]?[0-9]?[0-9]?[0-9]|3([01][0-9][0-9]|" + "2(0[0-9]|1[01])))$", string: sysVer )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
				}
				exit( 0 );
			}
			else {
				if(ContainsString( SP, "Service Pack 2" )){
					if(egrep( pattern: "^5\\.2\\.3790\\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|" + "3([0-6][0-9]|7[0-4])))$", string: sysVer )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
					}
					exit( 0 );
				}
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Win32k.sys" );
	if(sysVer){
		if( hotfix_check_sp( winVista: 2 ) > 0 ){
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_is_less( version: sysVer, test_version: "6.0.6001.18141" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18141", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
		}
		else {
			if(hotfix_check_sp( win2008: 2 ) > 0){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
				if(ContainsString( SP, "Service Pack 1" )){
					if(version_is_less( version: sysVer, test_version: "6.0.6001.18141" )){
						report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18141", install_path: sysPath );
						security_message( port: 0, data: report );
					}
					exit( 0 );
				}
			}
		}
	}
}

