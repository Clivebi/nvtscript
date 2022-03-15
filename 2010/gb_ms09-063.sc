if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801480" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-11-25 08:29:59 +0100 (Thu, 25 Nov 2010)" );
	script_cve_id( "CVE-2009-2512" );
	script_bugtraq_id( 36919 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Web Services on Devices API Remote Code Execution Vulnerability (973565)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3189" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-063" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attackers attackers to execute
  arbitrary code by sending a specially crafted message to the WSD TCP ports
  5357 or 5358." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "The flaws is caused by a memory corruption error in the Web Services on Devices
  API (WSDAPI), on both clients and servers, when processing a WSD message
  with malformed headers." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-063." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "973565" ) == 0){
	exit( 0 );
}
sysPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", item: "PathName" );
if(!sysPath){
	exit( 0 );
}
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: sysPath );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: sysPath + "\\System32\\Wsdapi.dll" );
dllVer = GetVer( file: file, share: share );
if(!dllVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3 ) > 0 ){
	SP = get_kb_item( "SMB/WinVista/ServicePack" );
	if(ContainsString( SP, "Service Pack 1" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6001.18306" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18306" );
			security_message( port: 0, data: report );
		}
		exit( 0 );
	}
	if(ContainsString( SP, "Service Pack 2" )){
		if(version_is_less( version: dllVer, test_version: "6.0.6002.18085" )){
			report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18085" );
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
			if(version_is_less( version: dllVer, test_version: "6.0.6001.18306" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6001.18306" );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		if(ContainsString( SP, "Service Pack 2" )){
			if(version_is_less( version: dllVer, test_version: "6.0.6002.18085" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "6.0.6002.18085" );
				security_message( port: 0, data: report );
			}
			exit( 0 );
		}
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

