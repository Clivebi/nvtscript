CPE = "cpe:/a:e107:e107";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800302" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-4786" );
	script_name( "e107 EasyShop plugin easyshop.php SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/6852" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
  SQL commands." );
	script_tag( name: "affected", value: "e107 version 0.7.13, EasyShop Plugin." );
	script_tag( name: "insight", value: "The flaw exists due to easyshop.php file in the EasyShop plugin, which can be
  exploited to conduct SQL injection by using execute commands via the category_id parameter." );
	script_tag( name: "solution", value: "Upgrade to e107 version 0.7.22 or later." );
	script_tag( name: "summary", value: "This host is running e107 and is prone to SQL injection vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://e107.org/edownload.php" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/e107_plugins/easyshop/easyshop.php?allcat";
sndReq = http_get( item: url, port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(egrep( pattern: "e107 Powered Website: EasyShop", string: rcvRes ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

