if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142675" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-30 07:34:56 +0000 (Tue, 30 Jul 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "AVM FRITZ!WLAN Repeater Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of AVM FRITZ!WLAN Repeater.

  This script performs HTTP(S) based detection of AVM FRITZ!WLAN Repeater." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
fingerprint["90ba7e91583241a9939cbf70b6d74403"] = "1750E";
fingerprint["0c3d43bd179516d9c8609b93c7311709"] = "310";
fingerprint["72d41ed2fce5d8c0e117efff045c8d6c"] = "450E";
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(!res){
	exit( 0 );
}
res = str_replace( string: res, find: raw_string( 0xC2, 0xA0 ), replace: " " );
if(ContainsString( res, "FRITZ!WLAN Repeater" ) && ( ContainsString( res, "\"GUI_IS_REPEATER\":true" ) || ContainsString( res, "facNotAllowedOr10Min" ) || ContainsString( res, "g_HelpWin" ) )){
	set_kb_item( name: "avm_fritz_wlanrepeater/detected", value: TRUE );
	set_kb_item( name: "avm_fritz_wlanrepeater/http/detected", value: TRUE );
	set_kb_item( name: "avm_fritz_wlanrepeater/http/port", value: port );
	model = "unknown";
	version = "unknown";
	mod = eregmatch( pattern: "\"bluBarTitle\":[ ]?\"FRITZ!WLAN Repeater ([^\"]+)\"", string: res );
	if(!isnull( mod[1] )){
		model = mod[1];
		set_kb_item( name: "avm_fritz_wlanrepeater/http/" + port + "/concluded", value: mod[0] );
	}
	if(model == "unknown"){
		url = "/css/default/images/kopfbalken_mitte.gif";
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!isnull( res )){
			md5 = hexstr( MD5( res ) );
			if(fingerprint[md5]){
				model = fingerprint[md5];
				set_kb_item( name: "avm_fritz_wlanrepeater/http/" + port + "/concluded", value: url );
			}
		}
	}
	set_kb_item( name: "avm_fritz_wlanrepeater/http/" + port + "/model", value: model );
	set_kb_item( name: "avm_fritz_wlanrepeater/http/" + port + "/version", value: version );
}
exit( 0 );

