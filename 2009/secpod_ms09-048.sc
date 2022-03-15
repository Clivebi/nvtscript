if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900838" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-4609", "CVE-2009-1925", "CVE-2009-1926" );
	script_bugtraq_id( 31545, 36269 );
	script_name( "Microsoft Windows TCP/IP Remote Code Execution Vulnerability (967723)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/967723" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2567" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-048" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code, and it
  may result in Denial of Service condition in an affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 2k  Service Pack 4 and prior

  - Microsoft Windows 2k3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "An error in the TCP/IP processing can be exploited to cause connections to
  hang indefinitely in a FIN-WAIT-1 or FIN-WAIT-2 state, and system to stop
  responding to new requests by flooding it using specially crafted packets
  with a TCP receive window size set to a very small value or zero." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-048." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5 ) > 0){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
if(hotfix_check_sp( win2003: 3, win2008: 3, winVista: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "967723" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\Tcpip.sys" );
	if(!sysVer){
		exit( 0 );
	}
}
if(hotfix_check_sp( win2003: 3 ) > 0){
	SP = get_kb_item( "SMB/Win2003/ServicePack" );
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "5.2.3790.4573" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4573", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
}
sysPath = smb_get_system32root();
if(sysPath){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\tcpip.sys" );
	if(!sysVer){
		exit( 0 );
	}
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6001.18311" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18311", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "6.0.6002.18091" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18091", install_path: sysPath );
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
			if(version_is_less( version: sysVer, test_version: "6.0.6001.18311" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18311", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "6.0.6002.18091" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6002.18091", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

