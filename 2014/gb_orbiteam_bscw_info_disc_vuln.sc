if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804297" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-2301" );
	script_bugtraq_id( 67284 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-16 11:22:00 +0530 (Fri, 16 May 2014)" );
	script_name( "OrbiTeam BSCW 'op' Parameter Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with OrbiTeam BSCW and is prone to information
  disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to read
  the filename of a document." );
	script_tag( name: "insight", value: "The flaw exists as the program associates filenames of documents with values
  mapped from the 'op' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain sensitive
  information by enumerating the names of all objects stored in BSCW without prior authentication." );
	script_tag( name: "affected", value: "OrbiTeam BSCW before version 5.0.8" );
	script_tag( name: "solution", value: "Upgrade to OrbiTeam BSCW version 5.0.8 or later." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/May/37" );
	script_xref( name: "URL", value: "https://xforce.iss.net/xforce/xfdb/93030" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126551" );
	script_xref( name: "URL", value: "https://www.redteam-pentesting.de/en/advisories/rt-sa-2014-003" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
bscwPort = http_get_port( default: 80 );
rcvRes = http_get_cache( item: "/", port: bscwPort );
if(!ContainsString( rcvRes, ">BSCW administrator<" )){
	exit( 0 );
}
req = http_get( item: "/pub/bscw.cgi/?op=inf", port: bscwPort );
rcvRes = http_keepalive_send_recv( port: bscwPort, data: req, bodyonly: TRUE );
if(ContainsString( rcvRes, "\"banner ruled_banner\"" )){
	rcvRes = eregmatch( pattern: "The document can be found <A HREF=\"" + "http://.*(/pub/bscw.cgi/(.*)/?op=inf)\">here", string: rcvRes );
	if(rcvRes[1]){
		url = rcvRes[1];
	}
	req = http_get( item: url, port: bscwPort );
	rcvRes = http_keepalive_send_recv( port: bscwPort, data: req, bodyonly: TRUE );
	if(ContainsString( rcvRes, "server_logo_bscw.jpg" )){
		rcvRes = eregmatch( pattern: "The document can be found <A HREF=\"" + "http://.*(/pub/bscw.cgi/(.*)/?op=inf)\">here", string: rcvRes );
		if(rcvRes[1]){
			url = rcvRes[1];
		}
		req = http_get( item: url, port: bscwPort );
		rcvRes = http_send_recv( port: bscwPort, data: req, bodyonly: TRUE );
		if(rcvRes && IsMatchRegexp( rcvRes, "<td.*class=\"iValueB\".*width=.*\">(.*)</td>" )){
			security_message( port: bscwPort );
			exit( 0 );
		}
	}
}
exit( 99 );

