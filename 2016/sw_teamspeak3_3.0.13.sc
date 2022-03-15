CPE = "cpe:/a:teamspeak:teamspeak3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111113" );
	script_version( "2020-11-12T13:45:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 13:45:39 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-08-15 15:00:00 +0200 (Mon, 15 Aug 2016)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "TeamSpeak 3 Server <= 3.0.13 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "General" );
	script_dependencies( "gb_teamspeak_detect.sc" );
	script_mandatory_keys( "teamspeak3_server/detected" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Aug/61" );
	script_xref( name: "URL", value: "http://forum.teamspeak.com/threads/126318-TeamSpeak-3-Server-3-0-13-2-released?p=434139#post434139" );
	script_tag( name: "summary", value: "TeamSpeak 3 server is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - Remote code execution

  - Information disclosure

  - Denial-of-Service" );
	script_tag( name: "impact", value: "Exploiting this vulnerability may allow an attacker execute
  arbitrary code on the TeamSpeak 3 server or cause a Denial-of-Service of the affected service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "TeamSpeak 3 server version up to 3.0.13." );
	script_tag( name: "solution", value: "Update your TeamSpeak 3 server to version 3.0.13.1 or later." );
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
if(version_in_range( version: ver, test_version: "3.0", test_version2: "3.0.13" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.0.13.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

