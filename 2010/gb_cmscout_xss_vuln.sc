if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800791" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_cve_id( "CVE-2010-2154" );
	script_bugtraq_id( 40442 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "CMScout Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39986" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58996" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/12806/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1288" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_cmscout_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "CMScout/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  script code." );
	script_tag( name: "affected", value: "CMScout version 2.09 and prior." );
	script_tag( name: "insight", value: "The flaw is caused by an input validation error in the 'search'
  module when processing the 'search' parameter in 'index.php' page." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running CMScout and is prone to Cross Site
  Scripting Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
cmsPort = http_get_port( default: 80 );
cmsVer = get_kb_item( "www/" + cmsPort + "/CMScout" );
if(!cmsVer){
	exit( 0 );
}
cmsVer = eregmatch( pattern: "^(.+) under (/.*)$", string: cmsVer );
if(cmsVer[2] != NULL){
	if(cmsVer[2] == "/"){
		cmsVer[2] = "";
	}
	filename = NASLString( cmsVer[2] + "/index.php?page=search&menuid=5" );
	useragent = http_get_user_agent();
	authVariables = "search=VT+XSS+Testing&content=1&Submit=Search";
	host = http_host_name( port: cmsPort );
	sndReq = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: en-us,en;q=0.5\\r\\n", "Accept-Encoding: gzip,deflate\\r\\n", "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\\r\\n", "Keep-Alive: 300\\r\\n", "Connection: keep-alive\\r\\n", "Referer: http://", host, filename, "\\r\\n", "Cookie: cmscout2=1f9f3e24745df5907a131c9acb41e5ef\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
	rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
	if(ContainsString( rcvRes, "(VT XSS Testing)" )){
		report = http_report_vuln_url( port: cmsPort, url: filename );
		security_message( port: cmsPort, data: report );
	}
}

