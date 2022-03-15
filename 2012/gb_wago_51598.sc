if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103396" );
	script_bugtraq_id( 51598 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WAGO Multiple Remote Vulnerabilities" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-23 15:14:54 +0100 (Mon, 23 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51598" );
	script_xref( name: "URL", value: "http://dsecrg.com/pages/vul/show.php?id=401" );
	script_xref( name: "URL", value: "http://dsecrg.com/pages/vul/show.php?id=402" );
	script_xref( name: "URL", value: "http://dsecrg.com/pages/vul/show.php?id=403" );
	script_xref( name: "URL", value: "http://dsecrg.com/pages/vul/show.php?id=404" );
	script_tag( name: "summary", value: "WAGO is prone to multiple security vulnerabilities, including:

  1. A security-bypass vulnerability

  2. Multiple information-disclosure vulnerabilities

  3. A cross-site request forgery vulnerability" );
	script_tag( name: "impact", value: "Successful attacks can allow an attacker to obtain sensitive
  information, bypass certain security restrictions, and perform
  unauthorized administrative actions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = NASLString( "/webserv/index.ssi" );
host = http_host_name( port: port );
if(http_vuln_check( port: port, url: url, pattern: "WAGO Ethernet Web-Based Management" )){
	default_credentials = make_list( "admin:wago",
		 "user:user",
		 "guest:guest" );
	for credential in default_credentials {
		userpass64 = base64( str: credential );
		url = "/webserv/cplcfg/security.ssi";
		req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n", "\\r\\n" );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<caption>Webserver Security" ) && ContainsString( buf, "Webserver and FTP User configuration" )){
			report = NASLString( "It was possible to login with the following credentials\\n\\nURL:User:Password\\n\\n", url, ":", credential );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

