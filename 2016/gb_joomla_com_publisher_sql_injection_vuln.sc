CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808236" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-06-27 14:52:23 +0530 (Mon, 27 Jun 2016)" );
	script_name( "Joomla Publisher component SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Joomla
  Publisher component and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "The flaw exists due to an insufficient
  validation of user supplied input via 'Itemid' parameter to 'index.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Joomla Publisher component version prior to 3.0.16" );
	script_tag( name: "solution", value: "Update to version 3.0.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/137595" );
	script_xref( name: "URL", value: "https://publisher.ijoomla.com/changelog" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://publisher.ijoomla.com/" );
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
url = dir + "/index.php?option=com_publisher&view=issues&Itemid='SQL-INJECTION-TEST&lang=en";
if(http_vuln_check( port: http_port, url: url, pattern: "You have an error in your SQL syntax", extra_check: make_list( "SQL-INJECTION-TEST",
	 "<title>1064 - Error: 1064</title>",
	 "id=\"pub-component\" class=\"pub-content\"" ) )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

