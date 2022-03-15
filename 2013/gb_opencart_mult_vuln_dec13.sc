CPE = "cpe:/a:opencart:opencart";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804161" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_bugtraq_id( 64162 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-09 19:52:35 +0530 (Mon, 09 Dec 2013)" );
	script_name( "OpenCart Multiple Vulnerabilities Dec-13" );
	script_tag( name: "summary", value: "The host is installed with OpenCart and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is vulnerable
or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Input passed via the 'zone_id' POST parameter to index.php is not properly sanitised before being returned to
    the user.

  - Insufficient authorization accessing 'system/logs/error.txt' which displays the full installation path within
    error messages.

  - Insufficient validity checks to verify the HTTP requests made by user." );
	script_tag( name: "affected", value: "OpenCart version 1.5.6 and probably previous versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary
HTML or script code, discloses the software's installation path resulting in a loss of confidentiality." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53036" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Dec/29" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/53036" );
	script_xref( name: "URL", value: "http://www.garda.ir/Opencart_Multiple_Vulnerabilities.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "opencart_detect.sc" );
	script_mandatory_keys( "OpenCart/installed" );
	script_require_ports( "Services/www", 80 );
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
url = dir + "/system/logs/error.txt";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "PHP Notice:  Undefined index:" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

