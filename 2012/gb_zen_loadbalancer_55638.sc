if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103574" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_bugtraq_id( 55638 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "ZEN Load Balancer Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55638" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-09-24 10:00:04 +0200 (Mon, 24 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "ZEN Load Balancer is prone to the following security vulnerabilities:

1. Multiple arbitrary command-execution vulnerabilities

2. Multiple information-disclosure vulnerabilities

3. An arbitrary file-upload vulnerability" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary commands,
upload arbitrary files to the affected computer, or disclose sensitive-
information." );
	script_tag( name: "affected", value: "ZEN Load Balancer 2.0 and 3.0 rc1 are vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 444 );
url = "/config/global.conf";
if(http_vuln_check( port: port, url: url, pattern: "Zen", extra_check: make_list( "\\$configdir",
	 "\\$logdir" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

