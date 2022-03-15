if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112309" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-06-21 12:10:11 +0200 (Thu, 21 Jun 2018)" );
	script_name( "NEC Communication Platforms Devices Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8001 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of NEC Communication Platforms Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is an NEC device from the reply." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
fingerprint["5ccacccda165a52ed35631cd1560173c"] = "SL1100";
fingerprint["8ff960ae800da220d5ddd499610236c6"] = "SV8100";
fingerprint["56fbf5a1166d69e1bb3b703962b280ac"] = "SV9100";
fingerprint["7c1b1fb135e268a230c13a373b2859cf"] = "UX5000";
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	file = "/";
	url = dir + file;
	res = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( res, "Server: Henry/1\\.1" ) && ContainsString( res, "<title>WebPro</title>" ) && ContainsString( res, "<frame name=\"banFrm\" src=\'Banner.htm\'" ) && ContainsString( res, "<frame name=\"mainFrm\" src=\'Login.htm\' />" )){
		set_kb_item( name: "nec/communication_platforms/detected", value: TRUE );
		model = "unknown";
		version = "unknown";
		images = make_list( "Images/Draco/PHILIPS/SL1100.PNG",
			 "Images/UniCorn/appTitle.png",
			 "Images/Cygnus/GE/appTitle.png",
			 "Images/Cygnus/US/appTitle.png",
			 "Images/Cygnus/PHILIPS/appTitle.png",
			 "Images/Cygnus/NA/appTitle.png" );
		for image in images {
			req = http_get( port: port, item: url + image );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(!isnull( res )){
				md5 = hexstr( MD5( res ) );
				if(fingerprint[md5]){
					model = fingerprint[md5];
					break;
				}
			}
		}
		version_url = url + "Login.htm";
		res = http_get_cache( item: version_url, port: port );
		version_match = eregmatch( pattern: "<br />([0-9.]+)</td>", string: res );
		if(version_match[1]){
			version = version_match[1];
			concluded_url = http_report_vuln_url( port: port, url: version_url, url_only: TRUE );
		}
		set_kb_item( name: "nec/communication_platforms/model", value: model );
		set_kb_item( name: "nec/communication_platforms/version", value: version );
		base = "cpe:/o:nec:communication_platforms_" + tolower( model );
		app = "NEC Communication Platforms";
		os_cpe = build_cpe( value: version, exp: "([0-9.]+)", base: base + ":" );
		if(!os_cpe){
			os_cpe = base;
		}
		os_register_and_report( os: app, cpe: os_cpe, banner_type: "HTTP Login Page", port: port, desc: "NEC Communication Platforms Devices Detection", runs_key: "unixoide" );
		register_and_report_cpe( app: app, ver: version, concluded: version_match[0], cpename: os_cpe, insloc: install, regPort: port, conclUrl: concluded_url );
		exit( 0 );
	}
}
exit( 0 );

