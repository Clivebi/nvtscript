CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903104" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_bugtraq_id( 57208 );
	script_cve_id( "CVE-2010-0635" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-01-29 14:06:14 +0530 (Tue, 29 Jan 2013)" );
	script_name( "Joomla! JEvents Component SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/81088" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/119361/joomlajevents-sql.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/joomla-jevents-150-sql-injection" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow the attackers to manipulate SQL queries by
injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Joomla! JEvents version 1.5.0" );
	script_tag( name: "insight", value: "The flaw is due to an input passed via the 'year' parameter to 'index.php'
(when 'option' is set to 'com_events') is not properly sanitised before being used in an SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Joomla! with JEvents component and is prone to sql
injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!joomlaPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: joomlaPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?option=com_events&amp;task=view_year&amp;year='";
if(http_vuln_check( port: joomlaPort, url: url, check_header: TRUE, pattern: "Argument #1 is not an array", extra_check: make_list( ">Warning<",
	 "array_merge()" ) )){
	report = http_report_vuln_url( port: joomlaPort, url: url );
	security_message( port: joomlaPort, data: report );
	exit( 0 );
}
exit( 99 );

