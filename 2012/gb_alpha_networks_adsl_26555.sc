if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103543" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Alpha Networks ADSL2/2+ Wireless Router version ASL-26555 Password Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/115663/Alpha-Networks-ADSL2-2-Wireless-Router-ASL-26555-Password-Disclosure.html" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-08-19 12:46:01 +0200 (Sun, 19 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Alpha Networks ADSL2/2+ ASL-26555 wireless router is prone to an information-disclosure
vulnerability that exposes sensitive information." );
	script_tag( name: "impact", value: "Successful exploits will allow unauthenticated attackers to obtain
sensitive information of the device such as administrative password,
which may aid in further attacks." );
	script_tag( name: "solution", value: "The only possible mitigation is to drop access to everyone from the outside
with a network level blocking configuration.
This can be done in the Advanced Configuration of the device.

You can also turn off the web panel, but you won't be able to manage the device." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8000 );
url = "/";
if(http_vuln_check( url: url, pattern: "<TITLE>ASL-26555", port: port )){
	url = "/APIS/returnJSON.htm";
	if(http_vuln_check( url: url, pattern: "\"USERNAME\":", port: port, extra_check: make_list( "\"PASSWORD\":",
		 "\"USER\":",
		 "\"RETURN\":" ) )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

