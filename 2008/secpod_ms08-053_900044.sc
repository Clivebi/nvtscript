if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900044" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)" );
	script_bugtraq_id( 31065 );
	script_cve_id( "CVE-2008-3008" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows : Microsoft Bulletins" );
	script_name( "Windows Media Encoder 9 Remote Code Execution Vulnerability (954156)" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-053" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS08-053." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error in the WMEX.DLL ActiveX
  control." );
	script_tag( name: "affected", value: "Microsoft Windows Media Encoder 9 on Microsoft Windows 2K/XP/2003." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "impact", value: "Remote attackers can execute arbitrary code, if a user views
  a specially crafted web page, and can successfully exploit to
  take complete control of an affected system to view, change, or
  delete, or create new accounts with full user rights." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("secpod_smb_func.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2k: 5, win2003: 3, win2008: 2, winVista: 2 ) <= 0){
	exit( 0 );
}
dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Windows Media Encoder 9", item: "DisplayIcon" );
dllPath = dllPath - "WMEnc.exe" + "wmex.dll";
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Windows Media Encoder 9" )){
	exit( 0 );
}
wmeName = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Windows Media Encoder 9", item: "DisplayName" );
if(ContainsString( wmeName, "Windows Media Encoder 9" )){
	if(hotfix_missing( name: "954156" ) == 0){
		exit( 0 );
	}
	vers = get_version( dllPath: dllPath );
	if(!vers){
		exit( 0 );
	}
	if(version_is_less( version: vers, test_version: "9.0.0.3359" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "9.0.0.3359", file_checked: dllPath );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}

