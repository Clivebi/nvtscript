if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801126" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Alleycode HTML Editor Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This script detects the installed version of Alleycode HTML Editor." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Alleycode HTML Editor Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
aheName = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\Kobeman_is1", item: "DisplayName" );
if(ContainsString( aheName, "Alleycode HTML Editor" )){
	aheVer = eregmatch( pattern: "Alleycode HTML Editor ([0-9.]+)", string: aheName );
	if(aheVer[1]){
		set_kb_item( name: "Alleycode-HTML-Editor/Ver", value: aheVer[1] );
		log_message( data: "Alleycode HTML Editor version " + aheVer[1] + " was detected on the host" );
		cpe = build_cpe( value: aheVer[1], exp: "^([0-9.]+)", base: "cpe:/a:konae:alleycode_html_editor:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

