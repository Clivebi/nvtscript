CPE = "cpe:/a:teamspeak:teamspeak3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111111" );
	script_version( "2020-11-12T13:45:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 13:45:39 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-07-23 15:00:00 +0200 (Sat, 23 Jul 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "TeamSpeak 3 Server < 3.0.12.4 Crashes On Malicious Input" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_teamspeak_detect.sc" );
	script_mandatory_keys( "teamspeak3_server/detected" );
	script_xref( name: "URL", value: "http://forum.teamspeak.com/threads/123250-TeamSpeak-3-Server-3-0-12-4-released" );
	script_tag( name: "summary", value: "This host is running a TeamSpeak 3 server and is prone to multiple server
  crashes on malicious input" );
	script_tag( name: "impact", value: "Exploiting this vulnerability may allow an attacker to crash the TeamSpeak 3
  server on malicious input." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "TeamSpeak 3 server version prior to 3.0.12.4." );
	script_tag( name: "solution", value: "Update your TeamSpeak 3 server to version 3.0.12.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: ver, test_version: "3.0", test_version2: "3.0.12.3" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.0.12.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

