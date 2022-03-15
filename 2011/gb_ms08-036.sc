if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801485" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)" );
	script_cve_id( "CVE-2008-1440", "CVE-2008-1441" );
	script_bugtraq_id( 29509, 29508 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_name( "Microsoft Pragmatic General Multicast (PGM)  Denial of Service Vulnerability (950762)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2008/1783" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-036" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a
  vulnerable system to become non-responsive." );
	script_tag( name: "affected", value: "- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1 and prior" );
	script_tag( name: "insight", value: "The flaw is due to the errors in Pragmatic General Multicast
  (PGM) protocol when handling PGM packets with an invalid option length
  field or fragment option." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-036." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 2, win2008: 2 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "950762" ) == 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\Rmcast.sys" );
if(!sysVer){
	exit( 0 );
}
if( hotfix_check_sp( xp: 4 ) > 0 ){
	SP = get_kb_item( "SMB/WinXP/ServicePack" );
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.3369" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.3369", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 3" )){
		if(version_is_less( version: sysVer, test_version: "5.1.2600.5598" )){
			report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.1.2600.5598", install_path: sysPath );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else {
	if( hotfix_check_sp( win2003: 3 ) > 0 ){
		SP = get_kb_item( "SMB/Win2003/ServicePack" );
		if(ContainsString( SP, "Service Pack 1" )){
			if(version_is_less( version: sysVer, test_version: "5.2.3790.3136" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.3136", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: sysVer, test_version: "5.2.3790.4290" )){
				report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4290", install_path: sysPath );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
	else {
		if( hotfix_check_sp( winVista: 2 ) > 0 ){
			SP = get_kb_item( "SMB/WinVista/ServicePack" );
			if(ContainsString( SP, "Service Pack 1" )){
				if(version_is_less( version: sysVer, test_version: "6.0.6001.18069" )){
					report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18069", install_path: sysPath );
					security_message( port: 0, data: report );
				}
				exit( 0 );
			}
		}
		else {
			if(hotfix_check_sp( win2008: 2 ) > 0){
				SP = get_kb_item( "SMB/Win2008/ServicePack" );
				if(ContainsString( SP, "Service Pack 1" )){
					if(version_is_less( version: sysVer, test_version: "6.0.6001.18069" )){
						report = report_fixed_ver( installed_version: sysVer, fixed_version: "6.0.6001.18069", install_path: sysPath );
						security_message( port: 0, data: report );
					}
					exit( 0 );
				}
			}
		}
	}
}
