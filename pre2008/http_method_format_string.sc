if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11801" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Format string on HTTP method name" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or contact your vendor and inform him
  of this vulnerability." );
	script_tag( name: "summary", value: "The remote web server seems to be vulnerable to a format string attack
  on the method name." );
	script_tag( name: "impact", value: "An attacker might use this flaw to make it crash or even execute
  arbitrary code on this host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
req = http_get( item: strcat( "/vt-test", rand_str(), ".html" ), port: port );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: req );
r = http_recv( socket: soc );
http_close_socket( soc );
if(!r){
	exit( 0 );
}
flag = 0;
flag2 = 0;
if(egrep( pattern: "[0-9a-fA-F]{8}", string: r )){
	flag = 1;
}
for bad in make_list( "%08x",
	 "%s",
	 "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x" ) {
	soc = http_open_socket( port );
	if(!soc){
		continue;
	}
	req2 = ereg_replace( string: req, pattern: "^GET", replace: bad );
	send( socket: soc, data: req2 );
	r = http_recv( socket: soc );
	http_close_socket( soc );
	if(egrep( pattern: "[0-9a-fA-F]{8}", string: r )){
		flag2++;
	}
}
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
if(flag2 && !flag){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

