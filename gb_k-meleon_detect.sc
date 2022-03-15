if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800891" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "K-Meleon Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of K-Meleon Browser." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "K-Meleon Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\K-Meleon";
kmeleonName = registry_get_sz( key: path, item: "DisplayName" );
if(ContainsString( kmeleonName, "K-Meleon" )){
	kmeleonVer = registry_get_sz( key: path, item: "DisplayVersion" );
	if(isnull( kmeleonVer )){
		kmeleonPath = registry_get_sz( key: path, item: "UninstallString" );
		kmeleonPath = ereg_replace( pattern: "\"", replace: "", string: kmeleonPath );
		readme = kmeleonPath - "nsuninst.exe" - "Uninstall.exe" + "readme.txt";
		readFile = smb_read_file( fullpath: readme, offset: 0, count: 2000 );
		ver = eregmatch( pattern: "v([0-9.]+)", string: readFile );
		if(!isnull( ver[1] )){
			kmeleonVer = ver[1];
		}
	}
	if(!isnull( kmeleonVer )){
		set_kb_item( name: "K-Meleon/Ver", value: kmeleonVer );
		log_message( data: "K-Meleon version " + kmeleonVer + " was detected on the host" );
		cpe = build_cpe( value: kmeleonVer, exp: "^([0-9.]+)", base: "cpe:/a:christophe_thibault:k-meleon:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}

