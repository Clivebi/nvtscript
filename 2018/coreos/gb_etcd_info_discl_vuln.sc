CPE = "cpe:/a:etcd:etcd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140888" );
	script_version( "2020-08-10T06:40:06+0000" );
	script_tag( name: "last_modification", value: "2020-08-10 06:40:06 +0000 (Mon, 10 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-27 08:55:55 +0700 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "etcd Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_etcd_detect.sc" );
	script_mandatory_keys( "etcd/installed" );
	script_tag( name: "summary", value: "etcd is prone to an information disclosure vulnerability if no authentication
is enabled. An attacker may read all stored key values which might contain sensitive information like passwords." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An unauthenticated attacker may gather sensitive information which could lead
to further attacks." );
	script_tag( name: "solution", value: "Enable authentication as referenced in the advisory." );
	script_xref( name: "URL", value: "https://coreos.com/etcd/docs/latest/v2/authentication.html" );
	script_xref( name: "URL", value: "https://elweb.co/the-security-footgun-in-etcd/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/v2/keys/?recursive=true";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "{\"action\":\"get\"" )){
	expert_info = "Response:\n" + res;
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report, expert_info: expert_info );
	exit( 0 );
}
exit( 99 );

