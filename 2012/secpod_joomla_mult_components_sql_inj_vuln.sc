CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902790" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-01-25 12:40:42 +0530 (Wed, 25 Jan 2012)" );
	script_name( "Joomla Jomdirectory and Advert Components SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/17430" );
	script_xref( name: "URL", value: "http://www.1337day.com/exploits/17427" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "Joomla Advert component Joomla Jomdirectory component." );
	script_tag( name: "insight", value: "The flaws are due to an:

  - Input passed via the 'type' parameter to 'index.php' (when option is set to com_jomdirectory) is not properly
sanitised before being used in a SQL query.

  - Input passed via the 'id', 'n_id' and 'Itemid' parameters to 'index.php' (when option is set to com_advert) is
properly sanitised before being used in a SQL query." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla with Jomdirectory and/or Advert components and is
prone to SQL injection vulnerabilities." );
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
pages = make_list( "/index.php?option=com_advert&id='",
	 "/index.php?option=com_jomdirectory&task=search&type='" );
for page in pages {
	url = dir + page;
	if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax;" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

