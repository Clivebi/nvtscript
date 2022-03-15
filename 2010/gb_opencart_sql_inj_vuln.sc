CPE = "cpe:/a:opencart:opencart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800734" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 38605 );
	script_cve_id( "CVE-2010-0956" );
	script_name( "OpenCart SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/1003-exploits/opencart-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "opencart_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OpenCart/installed" );
	script_tag( name: "insight", value: "The flaw exists in 'index.php' as it fails to sanitize user
  supplied data before using it in an SQL query. Remote attackers could exploit
  this to execute arbitrary SQL commands via the page parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running OpenCart and is prone to SQL Injection
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may leads to access
  or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "OpenCart version 1.3.2" );
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
url = dir + "/index.php?route=product/special&path=20&page='";
sndReq = http_get( item: url, port: port );
rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
if(( ContainsString( rcvRes, "SELECT *" ) && ContainsString( rcvRes, "ORDER BY" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

