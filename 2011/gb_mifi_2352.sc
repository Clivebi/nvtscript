if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103115" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-10 13:28:46 +0100 (Thu, 10 Mar 2011)" );
	script_bugtraq_id( 37962 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:N/A:N" );
	script_name( "Novatel Wireless MiFi 2352 Password Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/37962" );
	script_xref( name: "URL", value: "http://www.securitybydefault.com/2010/01/vulnerabilidad-en-modemrouter-3g.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "MiFi 2352 is prone to an information-disclosure vulnerability that may
  expose sensitive information." );
	script_tag( name: "impact", value: "Successful exploits will allow authenticated attackers to obtain
  passwords, which may aid in further attacks." );
	script_tag( name: "affected", value: "MiFi 2352 access point firmware 11.47.17 is vulnerable. Other versions
  may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/config.xml.sav" );
	if(http_vuln_check( port: port, url: url, pattern: "</WiFi>", extra_check: make_list( "<ssid>",
		 "<Secure>",
		 "<keyindex>" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

