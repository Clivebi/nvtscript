if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805114" );
	script_version( "2021-03-15T10:24:49+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-15 10:24:49 +0000 (Mon, 15 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-12-10 14:51:17 +0530 (Wed, 10 Dec 2014)" );
	script_name( "Microsoft Exchange Server Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Microsoft
  Exchange Server." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Exchange" ) && !registry_key_exists( key: "SOFTWARE\\Microsoft\\ExchangeServer" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(IsMatchRegexp( appName, "Microsoft Exchange Server [0-9.]+" ) && !ContainsString( appName, "Language Pack" )){
		ExVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(ExVer){
			insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insloc){
				continue;
			}
			set_kb_item( name: "MS/Exchange/Server/Ver", value: ExVer );
			set_kb_item( name: "MS/Exchange/Server/installed", value: TRUE );
			set_kb_item( name: "microsoft/exchange_server/detected", value: TRUE );
			if(ContainsString( appName, "Cumulative Update" )){
				set_kb_item( name: "MS/Exchange/Cumulative/Update", value: ExVer );
				set_kb_item( name: "MS/Exchange/Cumulative/Update/no", value: appName );
			}
			cpe = build_cpe( value: ExVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:exchange_server:" );
			if(!cpe){
				cpe = "cpe:/a:microsoft:exchange_server";
			}
			register_product( cpe: cpe, location: insloc, port: 0, service: "smb-login" );
			log_message( data: build_detection_report( app: appName, version: ExVer, install: insloc, cpe: cpe, concluded: ExVer ) );
		}
	}
}
exit( 0 );

