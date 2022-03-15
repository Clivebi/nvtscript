if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900171" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)" );
	script_cve_id( "CVE-2008-5002" );
	script_bugtraq_id( 32073 );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_name( "Chilkat Crypt ActiveX Control 'ChilkatCrypt2.dll' File Overwrite Vulnerability" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/6963" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32513/" );
	script_tag( name: "impact", value: "Successful exploitation will allow execution of arbitrary code." );
	script_tag( name: "affected", value: "Chilkat Crypt ActiveX Component version 4.3.2.1 and prior" );
	script_tag( name: "insight", value: "The vulnerability is due to the error in the 'ChilkatCrypt2.dll' ActiveX
  Control component that does not restrict access to the 'WriteFile()' method." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed Chilkat Crypt, which is prone to ActiveX
  Control based arbitrary file overwrite vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
enumKeys = registry_enum_keys( key: key );
for entry in enumKeys {
	if(ContainsString( registry_get_sz( key: key + entry, item: "DisplayName" ), "Chilkat Crypt ActiveX" )){
		if(egrep( pattern: "^4\\.([0-2](\\..*)?|3(\\.[0-2](\\.[01])?)?)$", string: registry_get_sz( key: key + entry, item: "DisplayVersion" ) )){
			clsid = "{3352B5B9-82E8-4FFD-9EB1-1A3E60056904}";
			regKey = "SOFTWARE\\Classes\\CLSID\\" + clsid;
			if(registry_key_exists( key: regKey )){
				activeKey = "SOFTWARE\\Microsoft\\Internet Explorer\\" + "ActiveX Compatibility\\" + clsid;
				killBit = registry_get_dword( key: activeKey, item: "Compatibility Flags" );
				if(killBit && ( int( killBit ) == 1024 )){
					exit( 0 );
				}
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		exit( 0 );
	}
}

