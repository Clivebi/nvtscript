if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900481" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)" );
	script_tag( name: "cvss_base", value: "8.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:C/A:C" );
	script_cve_id( "CVE-2008-6496" );
	script_bugtraq_id( 32664 );
	script_name( "Expert PDF EditorX ActiveX File Overwrite Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32990" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7358" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/47166" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker corrupt or overwrite
  arbitrary files on the user's system." );
	script_tag( name: "insight", value: "This flaw is due to an ActiveX control in Expert PDF EditorX file
  'VSPDFEditorX.ocx' providing insecure 'extractPagesToFile' method." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Expert PDF EditorX and is
  prone to ActiveX file overwrite vulnerability." );
	script_tag( name: "affected", value: "Expert PDF EditorX 'VSPDFEditorX.ocx' version 1.0.1910.0 and prior." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_activex.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	editorx = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( editorx, "eXPert PDF EditorX" )){
		ocxVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		break;
	}
}
if(ocxVer != NULL){
	if(version_is_less_equal( version: ocxVer, test_version: "1.0.1910.0" )){
		if(is_killbit_set( clsid: "{89F968A1-DBAC-4807-9B3C-405A55E4A279}" ) == 0){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
}

