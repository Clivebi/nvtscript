CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804720" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2014-4960" );
	script_bugtraq_id( 68676 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-07-24 16:09:39 +0530 (Thu, 24 Jul 2014)" );
	script_name( "Joomla! YouTube Gallery Component 'gallery.php' SQL Injection Vulnerability" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Joomla! YouTube Gallery Component and is prone
to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "Flaw is due to the /com_youtubegallery/models/gallery.php script not
properly sanitizing user-supplied input to the 'listid' and 'themeid' parameters." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary SQL
statements on the vulnerable system, which may leads to access or modify data in the underlying database." );
	script_tag( name: "affected", value: "Joomla! YouTube Gallery Component version 4.1.7, Prior versions may also be
affected." );
	script_tag( name: "solution", value: "Upgrade to version 4.1.9 or higher." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34087" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127497" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
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
url = dir + "/index.php?option=com_youtubegallery&view=youtubegallery" + "&listid=1'SQLInjectionTest&themeid=1";
if(http_vuln_check( port: http_port, url: url, check_header: FALSE, pattern: "You have an error in your SQL syntax.*SQLInjectionTest" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

