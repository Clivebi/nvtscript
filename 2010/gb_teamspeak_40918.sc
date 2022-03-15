CPE = "cpe:/a:teamspeak:teamspeak3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100682" );
	script_version( "2020-11-12T13:45:39+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 13:45:39 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 40918 );
	script_name( "TeamSpeak 3 Server < 3.0.0-beta25 Multiple Remote Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_teamspeak_detect.sc" );
	script_mandatory_keys( "teamspeak3_server/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40918" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/teamspeakrack-adv.txt" );
	script_xref( name: "URL", value: "http://forum.teamspeak.com/showthread.php?t=55646" );
	script_xref( name: "URL", value: "http://forum.teamspeak.com/showthread.php?t=55643" );
	script_tag( name: "summary", value: "TeamSpeak is prone to multiple remote vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - A security-pass vulnerability

  - A denial-of-service vulnerability

  - Multiple denial-of-service vulnerabilities due to a NULL-pointer dereference condition" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary commands
  within the context of the affected application, bypass certain security restrictions and crash the
  affected application. Other attacks are also possible." );
	script_tag( name: "solution", value: "Update to TeamSpeak 3.0.0-beta25 or later." );
	script_tag( name: "affected", value: "Versions prior to TeamSpeak 3.0.0-beta25 are vulnerable." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_kb_item( "teamspeak3_server/" + port )){
	exit( 0 );
}
if( ContainsString( ver, "build" ) ){
	vers = eregmatch( pattern: "([^ ]+)", string: ver );
	vers = vers[1];
}
else {
	vers = ver;
}
if(isnull( vers )){
	exit( 0 );
}
if(ContainsString( vers, "-beta" )){
	vers = str_replace( string: vers, find: "-beta", replace: "." );
}
if(version_is_less( version: vers, test_version: "3.0.0.25" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.0.0-beta25" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

