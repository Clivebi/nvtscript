if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800213" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-5667" );
	script_bugtraq_id( 31560 );
	script_name( "VirusBlokAda Personal AV Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6658" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow attacker to execute arbitrary codes
  through compressed rar archive and can cause memory corruption or service
  crash." );
	script_tag( name: "affected", value: "VirusBlokAda version 3.12.8.5 or prior." );
	script_tag( name: "insight", value: "Scanning archive files that are crafted maliciously causes application crash." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with VirusBlokAda and is prone to Denial
  of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
vbacheck = registry_key_exists( key: "SOFTWARE\\Vba32\\Loader" );
if(!vbacheck){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	vba = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( vba, "Vba32" )){
		vbaVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(vbaVer != NULL){
			if(version_is_less_equal( version: vbaVer, test_version: "3.12.8.5" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		exit( 0 );
	}
}

