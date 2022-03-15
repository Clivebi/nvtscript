if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902424" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0148", "CVE-2012-0149" );
	script_bugtraq_id( 51930, 51936 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-15 13:25:41 +0530 (Wed, 15 Feb 2012)" );
	script_name( "MS Windows Ancillary Function Driver Privilege Elevation Vulnerabilities (2645640)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow elevation of privilege if an attacker
  logs on to a user's system and runs a specially crafted application." );
	script_tag( name: "affected", value: "Microsoft Windows 2K3 Service Pack 2 and prior." );
	script_tag( name: "insight", value: "The flaws are caused due an error in Ancillary Function Driver (AFD) which
  does not properly validate input passed from user mode to the Windows kernel." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-009." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2645640" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-009" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2003: 3 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "2645640" ) == 0 )){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\drivers\\afd.sys" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win2003: 3 ) > 0){
	if(version_is_less( version: sysVer, test_version: "5.2.3790.4949" )){
		report = report_fixed_ver( installed_version: sysVer, fixed_version: "5.2.3790.4949", install_path: sysPath );
		security_message( port: 0, data: report );
	}
}

