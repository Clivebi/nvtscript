if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902331" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)" );
	script_cve_id( "CVE-2011-0498" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Nokia Multimedia Player Playlist Processing Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42852" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0083" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "insight", value: "The flaw is caused by a buffer overflow error when processing
playlists containing overly long data." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Nokia Multimedia Player and is prone
to buffer overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to crash an
affected application or compromise a vulnerable system by tricking a user into
opening a malicious playlist file." );
	script_tag( name: "affected", value: "Nokia Multimedia Player Version 1.00.55.5010 and prior" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Nokia\\Nokia Multimedia Player" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	nmpName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( nmpName, "Nokia Multimedia Player" )){
		nmpPath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!isnull( nmpPath )){
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: nmpPath );
			file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: nmpPath + "\\NokiaMMSViewer.exe" );
			nmpVer = GetVer( file: file, share: share );
			if(nmpVer != NULL){
				if(version_is_less_equal( version: nmpVer, test_version: "1.0.0.55" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

