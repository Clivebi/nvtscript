CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803682" );
	script_version( "$Revision: 11401 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-07-03 16:54:17 +0530 (Wed, 03 Jul 2013)" );
	script_name( "WordPress Feed Plugin SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jul/13" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122260/wpfeed-sql.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/wordpress-feed-sql-injection" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to manipulate SQL
queries by injecting arbitrary SQL code and gain sensitive information." );
	script_tag( name: "affected", value: "WordPress Feed Plugin" );
	script_tag( name: "insight", value: "Input passed via the 'nid' parameter to
'/wp-content/plugins/feed/news_dt.php' is not properly sanitised before being
used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running WordPress Feed plugin and is prone to sql
injection  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/feed/news_dt.php?nid=-[SQLi]--";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "mysql_fetch_array", extra_check: ">Warning" )){
	security_message( port: port );
	exit( 0 );
}

