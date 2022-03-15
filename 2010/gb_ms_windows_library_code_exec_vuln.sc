if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801399" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "MS Windows Insecure Library Loading Remote Code Execution Vulnerabilities (2269637)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/2269637" );
	script_xref( name: "URL", value: "http://www.network-box.com/aboutus/news/microsoft-advises-insecure-library-loading-vulnerability" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "insight", value: "The flaws are due to:

  - An error in the loading of dynamic link libraries (DLLs). If an application
    does not securely load DLL files, an attacker may be able to cause the
    application to load an arbitrary library.

  - A specific insecure programming practices that allow so-called
   'binary planting' or 'DLL preloading attacks', which allows the attacker to
    execute arbitrary code in the context of the user running the vulnerable
    application when the user opens a file from an untrusted location." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is prone to Remote Code Execution vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code or to
  elevate privileges." );
	script_tag( name: "affected", value: "- Microsoft Windows 7

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3, win7: 1 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2264107" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "Ntdll.dll" );
	if(sysVer){
		if( hotfix_check_sp( xp: 4 ) > 0 ){
			SP = get_kb_item( "SMB/WinXP/ServicePack" );
			if(ContainsString( SP, "Service Pack 3" )){
				if(version_is_less( version: sysVer, test_version: "5.1.2600.6007" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.6007", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		else {
			if(hotfix_check_sp( win2003: 3 ) > 0){
				SP = get_kb_item( "SMB/Win2003/ServicePack" );
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_is_less( version: sysVer, test_version: "5.2.3790.4737" )){
						report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4737", install_path: sysPath );
						security_message( port: 0, data: report );
					}
					exit( 0 );
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "Ntdll.dll" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 2 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6001.18499" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18499", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6002.18279" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18279", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if( hotfix_check_sp( win2008: 2 ) > 0 ){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6001.18499" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18499", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18279" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18279", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if(hotfix_check_sp( win7: 1 ) > 0){
			if(version_is_less( version: sysVer, test_version: "6.1.7600.16625" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.1.7600.16625", install_path: sysPath );
				security_message( port: 0, data: report );
			}
		}
	}
}

