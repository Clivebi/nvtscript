if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902157" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)" );
	script_cve_id( "CVE-2010-0812" );
	script_bugtraq_id( 39352 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Microsoft 'ISATAP' Component Spoofing Vulnerability (978338)" );
	script_xref( name: "URL", value: "http://isc.sans.org/diary.html?storyid=8626" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-029" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to spoof IPv6
  addresses and information disclosure and other attacks may also be
  possible." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'ISATAP' Component when handling 'IPv4'
  address, allows an attacker to spoof an IPv6 address so that it can bypass
  filtering devices that rely on the source IPv6 address." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-029." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "978338" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\Tcpip6.sys" );
	if(!sysVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if( ContainsString( SP, "Service Pack 2" ) ){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.3667" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.3667", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	else {
		if(ContainsString( SP, "Service Pack 3" )){
			if(version_is_less( version: sysVer, test_version: "5.1.2600.5935" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.5935", install_path: sysPath );
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
			if(version_is_less( version: sysVer, test_version: "5.2.3790.4662" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4662", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\Tcpip.sys" );
	if(!sysVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6001.18427" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18427", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6002.18209" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18209", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if(hotfix_check_sp( win2008: 3 ) > 0){
		SP = get_kb_item( "SMB/Win2008/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6001.18427" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18427", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18209" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18209", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

