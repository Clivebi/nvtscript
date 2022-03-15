if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800307" );
	script_version( "2019-07-26T13:41:14+0000" );
	script_tag( name: "last_modification", value: "2019-07-26 13:41:14 +0000 (Fri, 26 Jul 2019)" );
	script_tag( name: "creation_date", value: "2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5175" );
	script_bugtraq_id( 29989 );
	script_name( "AceFTP LIST Command Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://vuln.sg/aceftp3803-en.html" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30792" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/1954" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary code by
  tricking a user into downloading a directory containing files with
  specially crafted filenames from a malicious FTP server." );
	script_tag( name: "affected", value: "Visicom Medias AceFTP Freeware/Pro Version 3.80.3 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is due to input validation errors when processing FTP
  responses to a LIST command. These can be exploited by attackers when downloading the directories containing
  files with directory traversal specifiers in the filename." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with AceFTP and is prone to Directory
  Traversal Vulnerability." );
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
keys = registry_enum_keys( key: key );
for item in keys {
	aceName = registry_get_sz( item: "DisplayName", key: key + item );
	if(ContainsString( aceName, "AceFTP 3 Freeware" ) || ContainsString( aceName, "AceFTP 3 Pro" )){
		aceVer = registry_get_sz( item: "DisplayVersion", key: key + item );
		if(!aceVer){
			exit( 0 );
		}
		if(version_is_less_equal( version: aceVer, test_version: "3.80.3" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
