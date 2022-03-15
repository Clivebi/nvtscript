if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902791" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 44157 );
	script_cve_id( "CVE-2010-5082" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-15 11:45:39 +0530 (Wed, 15 Feb 2012)" );
	script_name( "MS Windows Color Control Panel Remote Code Execution Vulnerability (2643719)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026682" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-012" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to use the vulnerable application
  to open a file from a network share location that contains a specially crafted Dynamic Link Library (DLL) file." );
	script_tag( name: "affected", value: "Microsoft Windows Server 2008 Service Pack 2 and prior." );
	script_tag( name: "insight", value: "The flaw is due to a Color Control Panel library used by the Color
  Control Panel application is loading libraries in an insecure manner." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-012." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win2008: 3 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2643719" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
exeVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Colorcpl.exe" );
if(!exeVer){
	exit( 0 );
}
if(hotfix_check_sp( win2008: 3 ) > 0){
	if(version_is_less( version: exeVer, test_version: "6.0.6002.18552" ) || version_in_range( version: exeVer, test_version: "6.0.6002.20000", test_version2: "6.0.6002.22756" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

