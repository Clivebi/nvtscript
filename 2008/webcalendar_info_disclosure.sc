if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80021" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 17853 );
	script_xref( name: "OSVDB", value: "25280" );
	script_cve_id( "CVE-2006-2247" );
	script_name( "WebCalendar User Account Enumeration Disclosure Issue" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2008 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "webcalendar_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "webcalendar/installed" );
	script_tag( name: "summary", value: "The version of WebCalendar on the remote host is prone to a user
  account enumeration weakness in that in response to login attempts it returns different error messages
  depending on whether the user exists or the password is invalid." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to WebCalendar 1.0.4 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/433053/30/0/threaded" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/436263/30/0/threaded" );
	script_xref( name: "URL", value: "http://sourceforge.net/project/shownotes.php?group_id=3870&release_id=423010" );
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
host = http_host_name( port: port );
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	dir = matches[2];
	url = NASLString( dir, "/login.php" );
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res){
		continue;
	}
	if(ContainsString( res, "webcalendar_session=deleted; expires" ) && ContainsString( res, "<input name=\"login\" id=\"user\"" )){
		postdata = NASLString( "login=vt-test", unixtime(), "&", "password=vt-test" );
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!res){
			continue;
		}
		if(ContainsString( res, "Invalid login: no such user" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
		}
	}
}

