if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900267" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)" );
	script_bugtraq_id( 42855 );
	script_cve_id( "CVE-2010-3965" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Media Decompression Remote Code Execution Vulnerability (2447961)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2447961" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-094" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to load crafted DLL
  file and execute any code it contained." );
	script_tag( name: "affected", value: "- Microsoft Windows Media Encoder 9 with

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior" );
	script_tag( name: "insight", value: "The flaw is present when the Windows Media Encoder incorrectly restricts
  the path used for loading external libraries. An attacker could convince
  a user to open a legitimate '.prx' file that is located in the same network
  directory as a specially crafted dynamic link library (DLL) file." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS10-094." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
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
if(hotfix_missing( name: "2447961" ) == 0){
	exit( 0 );
}
wme9Installed = registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Windows Media Encoder 9" );
if(wme9Installed){
	wmekey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\wmenc.exe";
	wmeitem = "Path";
	wmePath = registry_get_sz( key: wmekey, item: wmeitem );
	dllVer = fetch_file_version( sysPath: wmePath, file_name: "wmenc.exe" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "9.0", test_version2: "9.0.0.3373" )){
			report = report_fixed_ver( installed_version: dllVer, vulnerable_range: "9.0 - 9.0.0.3373", install_path: wmePath );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}

