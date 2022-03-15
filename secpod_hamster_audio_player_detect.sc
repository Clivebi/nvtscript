if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800692" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Hamster Audio Player Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detection of the Hamster Audio Player." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(!appName || !ContainsString( appName, "Hamster" ) || !IsMatchRegexp( appName, "Hamster [0-9.]+" )){
		continue;
	}
	concluded = "Registry Key:   " + key + item + "\n";
	concluded += "DisplayName:    " + appName;
	location = "unknown";
	version = "unknown";
	vers = eregmatch( pattern: "Hamster ([0-9.]+([a-z]+)?)", string: appName );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "hamster/audio-player/detected", value: TRUE );
	register_and_report_cpe( app: "Hamster Audio Player", ver: version, concluded: concluded, base: "cpe:/a:ondanera.net:hamster_audio_player:", expr: "^([0-9.]+([a-z0-9]+)?)", insloc: location, regService: "smb-login", regPort: 0 );
	exit( 0 );
}
exit( 0 );

