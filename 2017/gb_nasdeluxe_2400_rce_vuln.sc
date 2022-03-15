if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140489" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-06 11:58:38 +0700 (Mon, 06 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "NASdeluxe NDL-2400R OS Command Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "NASdeluxe NDL-2400R is prone to an OS command injection vulnerability." );
	script_tag( name: "insight", value: "The language parameter in the web interface login request of the product
'NASdeluxe NDL-2400r' is vulnerable to an OS Command Injection as root." );
	script_tag( name: "vuldetect", value: "Check product." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40207/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>NASdeluxe NDL-2400R</title>" ) && ContainsString( res, "/usr/usrgetform.html?name=index" )){
	report = "NASdeluxe NDL-2400R has been detected.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

