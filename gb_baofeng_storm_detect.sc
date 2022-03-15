if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800913" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "BaoFeng Storm Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed BaoFeng Storm
  version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "BaoFeng Storm Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Storm2";
stormPath = registry_get_sz( key: key, item: "DisplayIcon" );
if(ContainsString( stormPath, "Storm" )){
	stormVer = registry_get_sz( key: key, item: "DisplayVersion" );
	if(stormVer != NULL){
		set_kb_item( name: "BaoFeng/Storm/Ver", value: stormVer );
		log_message( data: "BaoFeng Storm version " + stormVer + " was detected" + " on the host" );
		cpe = build_cpe( value: stormVer, exp: "^([0-9.]+)", base: "cpe:/a:baofeng:storm:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

