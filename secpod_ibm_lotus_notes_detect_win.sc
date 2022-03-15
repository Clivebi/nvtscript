if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901013" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IBM Lotus Notes Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of IBM Lotus Notes." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "IBM Lotus Notes Version Detection (Windows)";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Lotus\\Notes";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
notesPath = registry_get_sz( key: key, item: "Path" );
if(!isnull( notesPath )){
	path = notesPath + "notes.exe";
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
	lotusVer = GetVer( share: share, file: file );
	if(lotusVer != NULL){
		set_kb_item( name: "IBM/LotusNotes/Win/Ver", value: lotusVer );
		log_message( data: "IBM Lotus Notes version " + lotusVer + " running at location " + path + " was detected on the host" );
		cpe = build_cpe( value: lotusVer, exp: "^([0-9]\\.[0-9]+\\.[0-9]+)", base: "cpe:/a:ibm:lotus_notes:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

