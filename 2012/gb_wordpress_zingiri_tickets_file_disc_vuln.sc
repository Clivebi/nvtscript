CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802750" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-04-18 11:03:03 +0530 (Wed, 18 Apr 2012)" );
	script_name( "WordPress Zingiri Tickets Plugin File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/111904/wpzingiritickets-disclose.txt" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain sensitive
  information." );
	script_tag( name: "affected", value: "WordPress Zingiri Tickets Plugin version 2.1.2" );
	script_tag( name: "insight", value: "The flaw is due to insufficient permissions to the 'log.txt',
  which reveals administrative username and password hashes via direct http request." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with WordPress Zingiri Tickets plugin and
  is prone to file disclosure vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
url = NASLString( dir, "/wp-content/plugins/zingiri-tickets/log.txt" );
if(http_vuln_check( port: port, url: url, pattern: "\\[group_id\\]", extra_check: make_list( "\\[dept_id\\]",
	 "\\[passwd\\]",
	 "\\[email\\]" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

