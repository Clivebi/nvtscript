if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10416" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 2255 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Sambar /sysadmin directory 2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2000 Hendrik Scholz" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sambar_server_detect.sc" );
	script_require_ports( "Services/www", 3135 );
	script_mandatory_keys( "sambar_server/detected" );
	script_tag( name: "solution", value: "Change the passwords via the webinterface or use a real webserver
  like Apache." );
	script_tag( name: "summary", value: "The Sambar webserver is running.

  It provides a web interface for configuration purposes.

  The admin user has no password and there are some other default users without
  passwords. Everyone could set the HTTP-Root to c:\\ and delete existing files!

  *** This may be a false positive - go to http://example.com/sysadmin/ and
  have a look at it by yourself." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 3135 );
url = "/sysadmin/dbms/dbms.htm";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(egrep( pattern: "[sS]ambar", string: res )){
	if(ereg( pattern: "^HTTP/1\\.[01] 403", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

