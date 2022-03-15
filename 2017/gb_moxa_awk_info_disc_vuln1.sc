CPE_PREFIX = "cpe:/h:moxa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106741" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-11 14:59:45 +0200 (Tue, 11 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-20 13:44:00 +0000 (Thu, 20 Apr 2017)" );
	script_cve_id( "CVE-2016-8725" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Moxa AWK Series Systemlog Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moxa_awk_detect.sc" );
	script_mandatory_keys( "moxa_awk/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Moxa AWK series wireless access points are prone to a systemlog.log
  information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a HTTP request and checks the response." );
	script_tag( name: "insight", value: "The file systemlog.log can be accessed without any authentication which
  might reveal sensitive information." );
	script_tag( name: "impact", value: "An unauthenticated attacker may obtain sensitive information." );
	script_tag( name: "solution", value: "Update to version 1.4 or later." );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0239/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/systemlog.log";
if(http_vuln_check( port: port, url: url, pattern: "\\([0-9]+\\) [0-9/]+,[0-9]+h:[0-9]+m:[0-9]+s", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

