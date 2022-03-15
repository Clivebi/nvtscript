if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15752" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2004-1506", "CVE-2004-1507", "CVE-2004-1508", "CVE-2004-1509", "CVE-2004-1510" );
	script_bugtraq_id( 11651 );
	script_name( "WebCalendar SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "webcalendar_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webcalendar/installed" );
	script_tag( name: "summary", value: "The remote installation of WebCalendar may allow an attacker to cause
  an SQL Injection vulnerability in the program allowing an attacker to
  cause the program to execute arbitrary SQL statements." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
install = get_kb_item( NASLString( "www/", port, "/webcalendar" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	loc = matches[2];
	req = http_get( item: NASLString( loc, "/view_entry.php?id=1'&date=1" ), port: port );
	r = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!r){
		exit( 0 );
	}
	if(egrep( pattern: "You have an error in your SQL syntax", string: r ) || egrep( pattern: "SELECT webcal_entry.cal_id FROM webcal_entry", string: r )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

