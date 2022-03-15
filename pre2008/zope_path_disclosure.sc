if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11234" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5806 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Zope Installation Path Disclosure" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Web Servers" );
	script_dependencies( "gb_zope_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zope/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to Zope 2.5.1b1 / 2.6.0b1 or later." );
	script_tag( name: "summary", value: "The remote web server contains the Zope application server that is prone to
  information disclosure." );
	script_tag( name: "insight", value: "There is a minor security problem in all releases of Zope prior to
  version 2.5.1b1 - they reveal the installation path when an invalid
  XML RPC request is sent." );
	exit( 0 );
}
CPE = "cpe:/a:zope:zope";
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
s = http_open_socket( port );
if(!s){
	exit( 0 );
}
vt_strings = get_vt_strings();
url = "/Foo/Bar/" + vt_strings["default"];
req = http_post( port: port, item: url );
send( socket: s, data: req );
a = http_recv( socket: s );
http_close_socket( s );
if(egrep( string: a, pattern: "(File|Bobo-Exception-File:) +(/[^/]*)*/[^/]+.py" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

