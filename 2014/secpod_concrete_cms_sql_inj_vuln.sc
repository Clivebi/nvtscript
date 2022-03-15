CPE = "cpe:/a:concrete5:concrete5";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903511" );
	script_version( "2021-08-04T10:08:11+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-19 16:18:17 +0530 (Wed, 19 Feb 2014)" );
	script_name( "Concrete5 CMS SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "concrete5/installed" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/21919" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/31735/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125280/concrete5-sql.txt" );
	script_tag( name: "summary", value: "The host is installed with Concrete5 CMS and is prone to sql injection
  vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it
  is possible to execute sql query." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of 'cID' parameter passed to
  '/index.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands in applications database and gain complete control over the vulnerable
  web application." );
	script_tag( name: "affected", value: "Concrete5 CMS version 5.6.3.4" );
	script_tag( name: "solution", value: "Upgrade to version 5.6.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://www.concrete5.org" );
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
url = dir + "/index.php/?arHandle=Main&bID=34&btask=passthru&ccm_token=" + "1392630914:be0d09755f653afb162d041a33f5feae&cID[$owmz]=1&" + "method=submit_form";
if(http_vuln_check( port: port, url: url, pattern: ">mysqlt error:", extra_check: make_list( "Pages.cID = Array",
	 "EXECUTE.\"select Pages.cID" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

