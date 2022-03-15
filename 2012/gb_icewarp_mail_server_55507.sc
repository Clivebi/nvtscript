CPE = "cpe:/a:icewarp:mail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103565" );
	script_bugtraq_id( 55507 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2020-11-05T10:18:37+0000" );
	script_name( "IceWarp Mail Server <= 10.4.3 'raw.php' Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55507" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/50441" );
	script_tag( name: "last_modification", value: "2020-11-05 10:18:37 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-09-13 10:46:19 +0200 (Thu, 13 Sep 2012)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_icewarp_consolidation.sc" );
	script_mandatory_keys( "icewarp/mailserver/http/detected" );
	script_tag( name: "summary", value: "IceWarp Mail Server is prone to an information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue may allow an attacker to obtain sensitive information that may aid in further attacks." );
	script_tag( name: "affected", value: "IceWarp Mail Server 10.4.3 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/pda/controller/raw.php";
if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

