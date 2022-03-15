CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901203" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)" );
	script_bugtraq_id( 49303 );
	script_cve_id( "CVE-2011-3192" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Apache HTTP Server Range Header Denial of Service Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_mandatory_keys( "apache/http_server/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17696" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/104441" );
	script_xref( name: "URL", value: "http://marc.info/?l=apache-httpd-dev&m=131420013520206&w=2" );
	script_xref( name: "URL", value: "http://mail-archives.apache.org/mod_mbox/httpd-dev/201108.mbox/%3CCAAPSnn2PO-d-C4nQt_TES2RRWiZr7urefhTKPWBC1b+K1Dqc7g@mail.gmail.com%3E" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote unauthenticated attackers to
  cause a denial of service." );
	script_tag( name: "affected", value: "Apache HTTP Server 1.3.x, 2.0.x through 2.0.64 and 2.2.x through 2.2.19." );
	script_tag( name: "insight", value: "The flaw is caused the way Apache httpd web server handles certain requests
  with multiple overlapping ranges, which causes significant memory and CPU
  usage on the server leading to application crash and system can become unstable." );
	script_tag( name: "solution", value: "Please see the references for a fix to mitigate this issue." );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial of service vulnerability." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
req1 = NASLString( "HEAD / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept-Encoding: gzip\\r\\n", "Range: bytes=0-100\\r\\n", "Connection: close\\r\\n", "\\r\\n" );
range_bytes = "";
for(i = 0;i < 30;i++){
	range_bytes += "5-" + i;
	if(i < 29){
		range_bytes += ",";
	}
}
req2 = NASLString( "HEAD / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept-Encoding: gzip\\r\\n", "Range: bytes=" + range_bytes + "\\r\\n", "Connection: close\\r\\n", "\\r\\n" );
res1 = http_send_recv( port: port, data: req1 );
res2 = http_send_recv( port: port, data: req2 );
if(IsMatchRegexp( res1, "HTTP\\/[0-9]\\.[0-9] 206 Partial Content" ) && IsMatchRegexp( res2, "HTTP\\/[0-9]\\.[0-9] 206 Partial Content" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

