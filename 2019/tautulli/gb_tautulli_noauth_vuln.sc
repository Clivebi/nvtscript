CPE = "cpe:/a:tautulli:tautulli";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143151" );
	script_version( "2019-11-20T06:26:35+0000" );
	script_tag( name: "last_modification", value: "2019-11-20 06:26:35 +0000 (Wed, 20 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-20 05:36:55 +0000 (Wed, 20 Nov 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Tautulli Accessible Without Authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_tautulli_detect.sc" );
	script_mandatory_keys( "tautulli/detected" );
	script_tag( name: "summary", value: "Tautulli is accessible without any authentication." );
	script_tag( name: "vuldetect", value: "Checks if Tautulli is accessible without authentication." );
	script_tag( name: "impact", value: "An unauthenticated attacker may access Tautulli and read/modify settings
  and other data." );
	script_tag( name: "solution", value: "Enable authentication." );
	script_xref( name: "URL", value: "https://github.com/Tautulli/Tautulli-Wiki/wiki/Frequently-Asked-Questions#q-how-can-i-access-tautulli-outside-my-home-network" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_kb_item( "tautulli/" + port + "/noauth" )){
	exit( 99 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
security_message( port: port );
exit( 0 );

