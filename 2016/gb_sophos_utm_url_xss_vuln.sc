CPE = "cpe:/a:sophos:unified_threat_management";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807519" );
	script_version( "2021-09-29T15:21:15+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 15:21:15 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-04 18:36:07 +0530 (Fri, 04 Mar 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Sophos UTM URL Reflected XSS Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sophos_utm_http_detect.sc" );
	script_mandatory_keys( "sophos/utm/http/detected" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "summary", value: "Sophos UTM is prone to a reflected cross-site scripting (XSS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  validation of user supplied input via the 'url' of a web site protected by
  Sophos UTM 525." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session, read
  arbitrary files and to trigger specific actions." );
	script_tag( name: "affected", value: "Sophos UTM version 9.352-6 and 94988." );
	script_tag( name: "solution", value: "Upgrade to Sophos UTM 9.354 or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/537662" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/136019/SYSS-2016-009.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/%3Cscript%3Ealert(document.cookie)%3C/script%3E";
if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script", extra_check: "<title>Request blocked</title>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

