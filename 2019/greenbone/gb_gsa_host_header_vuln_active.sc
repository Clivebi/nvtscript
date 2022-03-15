CPE = "cpe:/a:greenbone:greenbone_security_assistant";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108664" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-10-10 06:28:14 +0000 (Thu, 10 Oct 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-25 01:14:00 +0000 (Fri, 25 Jun 2021)" );
	script_cve_id( "CVE-2018-25016" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Greenbone Security Assistant (GSA) < 7.0.3 Host Header Injection Vulnerability - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gsa_detect.sc", "gb_greenbone_os_consolidation.sc", "smtp_settings.sc" );
	script_mandatory_keys( "greenbone_security_assistant/pre80/detected" );
	script_exclude_keys( "greenbone/gos/detected" );
	script_tag( name: "summary", value: "Greenbone Security Assistant (GSA) is prone to an HTTP host
  header injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can potentially use this vulnerability in a phishing
  attack." );
	script_tag( name: "affected", value: "Greenbone Security Assistant (GSA) before version 7.0.3." );
	script_tag( name: "solution", value: "Update to version 7.0.3 or later." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_xref( name: "URL", value: "https://github.com/greenbone/gsa/pull/318" );
	script_xref( name: "URL", value: "https://github.com/greenbone/gsa/releases/tag/v7.0.3" );
	exit( 0 );
}
if(get_kb_item( "greenbone/gos/detected" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("smtp_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
domain = get_3rdparty_domain();
replace = "Host: " + domain;
url = dir + "/";
req = http_get( port: port, item: url );
req = ereg_replace( string: req, pattern: "(Host: [^\r\n]+)", replace: replace );
res = http_keepalive_send_recv( port: port, data: req );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 303" )){
	exit( 0 );
}
if(found = egrep( string: res, pattern: "<html><body>Code 303 - Redirecting to .+" + domain + ".+<a/></body></html>", icase: TRUE )){
	info["HTTP Method"] = "GET";
	info["URL"] = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	info["\"Host\" header"] = replace;
	report = "By doing the following request:\n\n";
	report += text_format_table( array: info ) + "\n\n";
	report += "it was possible to redirect to an external ";
	report += "domain via an HTTP Host header injection attack.";
	report += "\n\nResult:\n\n" + chomp( found );
	expert_info = "Request:\n" + req + "Response:\n" + res + "\n";
	security_message( port: port, data: report, expert_info: expert_info );
	exit( 0 );
}
exit( 99 );

