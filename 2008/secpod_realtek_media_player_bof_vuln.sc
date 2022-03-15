if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900067" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5664" );
	script_bugtraq_id( 32860 );
	script_name( "Realtek Media Player Playlist Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7492" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47380" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code to cause buffer overflow and can lead to application crash." );
	script_tag( name: "affected", value: "Realtek Media Player A4.06 (5.36) and prior on Windows." );
	script_tag( name: "insight", value: "The issue is due to improper bounds checking when processing
  playlist files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has Realtek Media Player installed and is prone to
  buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.realtek.com.tw/downloads/" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Realtek Semiconductor Corp." )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	if(ContainsString( registry_get_sz( key: key + item, item: "DisplayName" ), "Realtek" )){
		rmpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!rmpVer){
			exit( 0 );
		}
		if(version_is_less_equal( version: rmpVer, test_version: "5.36" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
		exit( 0 );
	}
}

