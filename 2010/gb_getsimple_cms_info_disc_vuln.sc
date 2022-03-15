CPE = "cpe:/a:get-simple:getsimple_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801551" );
	script_version( "2021-08-10T12:11:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 12:11:50 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "GetSimple CMS < 2.03 Administrative Credentials Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_getsimple_cms_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "getsimple_cms/http/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/15605/" );
	script_tag( name: "insight", value: "GetSimple does not use a SQL Database. Instead it uses a '.xml'
  files located at '/GetSimple/data'. The administrators username and password hash can be obtained
  by navigating to the '/data/other/user.xml' xml file." );
	script_tag( name: "solution", value: "Update to version 2.03 or later." );
	script_tag( name: "summary", value: "GetSimple CMS is prone to an administrative credentials
  disclosure vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain
  sensitive information." );
	script_tag( name: "affected", value: "GetSimple CMS 2.01 and 2.02 are known to be affected." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
url = dir + "/data/other/user.xml";
if(http_vuln_check( port: port, url: url, pattern: "(<PWD>.*</PWD>)" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

