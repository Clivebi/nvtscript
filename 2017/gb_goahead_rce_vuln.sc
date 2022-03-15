if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140609" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-19 08:55:23 +0700 (Tue, 19 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-20 01:29:00 +0000 (Fri, 20 Apr 2018)" );
	script_cve_id( "CVE-2017-17562" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "GoAhead Server RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_goahead_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "embedthis/goahead/detected" );
	script_tag( name: "summary", value: "Embedthis GoAhead is prone to a remote code execution vulnerability." );
	script_tag( name: "insight", value: "Embedthis GoAhead allows remote code execution if CGI is enabled and a CGI
  program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using
  untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic
  linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD.
  An attacker can POST their shared object payload in the body of the request, and reference it using
  /proc/self/fd/0." );
	script_tag( name: "impact", value: "An unauthenticated attacker may execute arbitrary code." );
	script_tag( name: "vuldetect", value: "Checks if CGI scripting is enabled." );
	script_tag( name: "affected", value: "GoAhead versions prior to 3.6.5." );
	script_tag( name: "solution", value: "Updated to version 3.6.5 or later. As a migitation step disable CGI
support." );
	script_xref( name: "URL", value: "https://www.elttam.com.au/blog/goahead/" );
	script_xref( name: "URL", value: "https://github.com/embedthis/goahead/issues/249" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/43360/" );
	exit( 0 );
}
CPE = "cpe:/a:embedthis:goahead";
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: port );
url = "/cgi-bin/c8fed00eb2e87f1cee8e90ebbe870c190ac3848c";
if(http_vuln_check( port: port, url: url, pattern: "CGI process file does not exist", check_header: TRUE )){
	report = "CGI scripting is enabled.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

