if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800893" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Lunascape Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Lunascape Browser." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Lunascape Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
luna = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for item in make_list( "Lunascape4",
	 "Lunascape5" ) {
	lunaName = registry_get_sz( key: luna + item, item: "DisplayName" );
	if(ContainsString( lunaName, "Lunascape" )){
		lunaPath = registry_get_sz( key: luna + item, item: "UninstallString" );
		if(lunaPath){
			lunaPath = lunaPath - "Uninstall.exe" + "Luna.exe";
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: lunaPath );
			lfile = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: lunaPath );
			lunaVer = GetVer( file: lfile, share: share );
		}
		if(!isnull( lunaVer )){
			set_kb_item( name: "Lunascape/Ver", value: lunaVer );
			log_message( data: "Lunascape version " + lunaVer + " was detected on the host" );
			cpe = build_cpe( value: lunaVer, exp: "^([0-9.]+)", base: "cpe:/a:lunascape:lunascape:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

