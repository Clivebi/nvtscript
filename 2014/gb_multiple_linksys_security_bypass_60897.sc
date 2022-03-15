if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105041" );
	script_bugtraq_id( 60897 );
	script_cve_id( "CVE-2013-5122" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-05-05T10:19:36+0000" );
	script_name( "Multiple Cisco Linksys Products Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60897" );
	script_tag( name: "last_modification", value: "2020-05-05 10:19:36 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "creation_date", value: "2014-06-05 11:24:23 +0200 (Thu, 05 Jun 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 8083 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to bypass certain
  security restrictions and gain unauthorized access to the affected device." );
	script_tag( name: "vuldetect", value: "Connect to port 8083 and check the response." );
	script_tag( name: "insight", value: "The device listens on port 8083 with the same interface as port
  80, but completely circumvents HTTP/S authentication granting admin privileges on the device." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Multiple Cisco Linksys products are prone to a security-bypass
  vulnerability." );
	script_tag( name: "affected", value: "Cisco Linksys EA2700 running firmware 1.0.14

  Cisco Linksys EA3500 running firmware 1.0.30

  Cisco Linksys E4200 running firmware 2.0.36

  Cisco Linksys EA4500 running firmware 2.0.36" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
port = 8083;
if(!get_port_state( port )){
	exit( 0 );
}
if(http_vuln_check( port: port, url: "/Management.asp", pattern: "<TITLE>Management</TITLE>", extra_check: "http_passwd" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

