if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900080" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0095", "CVE-2009-0096", "CVE-2009-0097" );
	script_bugtraq_id( 33659, 33660, 33661 );
	script_name( "Vulnerabilities in Microsoft Office Visio Could Allow Remote Code Execution (957634)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/957634" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-005" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could lead to memory corruption by sending
  a specially crafted Visio file." );
	script_tag( name: "affected", value: "Microsoft Office Visio 2002/2003/2007." );
	script_tag( name: "insight", value: "- Error exists when parsing object data during opening of Visio files.

  - Pop-Up error while copying object data in memory.

  - Error while handling of memory when opening Visio files." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS09-005." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2k: 5, xp: 4, win2003: 3 ) <= 0){
	exit( 0 );
}
ovPath = registry_get_sz( item: "Path", key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\visio.exe" );
if(!ovPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: ovPath, file_name: "visio.exe" );
if(!exeVer){
	exit( 0 );
}
if(version_in_range( version: exeVer, test_version: "10.0", test_version2: "10.0.6885.3" ) || version_in_range( version: exeVer, test_version: "11.0", test_version2: "11.0.8206.0" ) || version_in_range( version: exeVer, test_version: "12.0", test_version2: "12.0.6325.4999" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

