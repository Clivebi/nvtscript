if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800895" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Maxthon Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Maxthon Browser." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Maxthon Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
maxthon = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
for item in make_list( "Maxthon",
	 "Maxthon2",
	 "Maxthon3" ) {
	maxthonName = registry_get_sz( key: maxthon + item, item: "DisplayName" );
	if(ContainsString( maxthonName, "Maxthon" )){
		maxthonVer = registry_get_sz( key: maxthon + item, item: "DisplayVersion" );
		if(isnull( maxthonVer )){
			maxthonPath = registry_get_sz( key: maxthon + item, item: "DisplayIcon" );
			if(ContainsString( maxthonPath, "Mx3Uninstall.exe" )){
				maxthonPath = maxthonPath - "Mx3Uninstall.exe" + "Maxthon.exe";
			}
			share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: maxthonPath );
			mfile = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: maxthonPath );
			maxthonVer = GetVer( file: mfile, share: share );
		}
		if(!isnull( maxthonVer )){
			set_kb_item( name: "Maxthon/Ver", value: maxthonVer );
			log_message( data: "Maxthon version " + maxthonVer + " was detected on the host" );
			cpe = build_cpe( value: maxthonVer, exp: "^([0-9.]+)", base: "cpe:/a:maxthon:maxthon_browser:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

