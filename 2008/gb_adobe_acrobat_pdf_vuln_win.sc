if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800078" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-5331" );
	script_bugtraq_id( 32610 );
	script_name( "Adobe Acrobat 9 PDF Document Encryption Weakness Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://blogs.adobe.com/security/2008/12/acrobat_9_and_password_encrypt.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to steal or guess document's
  password via a brute force attacks." );
	script_tag( name: "affected", value: "Adobe Acrobat version 9.0 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to the way it handles encryption standards." );
	script_tag( name: "solution", value: "Upgrade Adobe Acrobat version 9.3.2 or later." );
	script_tag( name: "summary", value: "This host has Adobe Acrobat installed and is prone to encryption
  weakness vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Adobe" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	adobeName = registry_get_sz( item: "DisplayName", key: key + item );
	if(ContainsString( adobeName, "Adobe Acrobat" )){
		adobeVer = registry_get_sz( item: "DisplayVersion", key: key + item );
		if(!adobeVer){
			exit( 0 );
		}
		if(IsMatchRegexp( adobeVer, "^9\\.0(\\.0)?$" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}

