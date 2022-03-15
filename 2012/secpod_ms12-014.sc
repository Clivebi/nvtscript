if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902792" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2010-3138" );
	script_bugtraq_id( 42730 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-15 13:02:52 +0530 (Wed, 15 Feb 2012)" );
	script_name( "MS Windows Indeo Codec Remote Code Execution Vulnerability (2661637)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026683" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2661637" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-014" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to load arbitrary libraries by
  tricking a user into opening an AVI file located on a remote WebDAV or SMB share via an application using the filter." );
	script_tag( name: "affected", value: "Microsoft Windows XP Service Pack 3 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'Indeo' filter, it is loading libraries
  (e.g. iacenc.dll) in an insecure manner." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-014." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4 ) <= 0){
	exit( 0 );
}
if(hotfix_missing( name: "2661637" ) == 0){
	exit( 0 );
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
path = sysPath + "\\system32\\Iacenc.dll";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
if(share && file){
	dllSize = get_file_size( share: share, file: file );
	if(!dllSize){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\Iacenc.dll" );
if(dllVer){
	if(version_is_less( version: dllVer, test_version: "1.0.0.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

