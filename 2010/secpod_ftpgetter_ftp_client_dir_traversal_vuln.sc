if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902233" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)" );
	script_cve_id( "CVE-2010-3103" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FTPGetter FTP Client Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41069" );
	script_xref( name: "URL", value: "http://www.htbridge.ch/advisory/directory_traversal_in_ftpgetter.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw exists due to error in handling of certain crafted file
names. It does not properly sanitise filenames containing directory traversal
sequences that are received from an FTP server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with FTPGetter FTP Client and is prone to
directory traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to write files into
a user's Startup folder to execute malicious code when the user logs on." );
	script_tag( name: "affected", value: "FTPGetter FTP Client 3.51.0.05 and prior." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	fgName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( fgName, "FTPGetter" )){
		fgpath = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if(!isnull( fgpath )){
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: fgpath );
			file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: fgpath );
			fgVer = GetVer( file: file, share: share );
			if(fgVer != NULL){
				if(version_is_less_equal( version: fgVer, test_version: "3.51.0.05" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

