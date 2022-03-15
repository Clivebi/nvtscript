CPE_PREFIX = "cpe:/o:siemens:scalance_";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103907" );
	script_bugtraq_id( 62341 );
	script_cve_id( "CVE-2013-5709" );
	script_version( "2021-04-28T12:47:22+0000" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_name( "Siemens Scalance X-200 Series Switches Insufficient Entropy Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62341" );
	script_xref( name: "URL", value: "http://blog.ioactive.com/2014/02/the-password-is-irrelevant-too.html" );
	script_tag( name: "last_modification", value: "2021-04-28 12:47:22 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-02-17 17:18:56 +0100 (Mon, 17 Feb 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_simatic_scalance_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "siemens/simatic/scalance/http/detected" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to hijack web sessions
  over the network without authentication. Other attacks are also possible." );
	script_tag( name: "vuldetect", value: "Check if it is possible to read the configuration file with an
  HTTP GET request." );
	script_tag( name: "insight", value: "By requesting /fs/cfgFile.cfg it is possible to read the config
  of the remote device." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Siemens Scalance X-200 Series switches are prone to a
  vulnerability in the entropy of random number generator." );
	script_tag( name: "affected", value: "Siemens Scalance X-200 Series switches running firmware
  versions prior to 5.0.0 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!get_app_location( port: port, cpe: cpe )){
	exit( 0 );
}
url = "/fs/cfgFile.cfg";
if(http_vuln_check( port: port, url: url, pattern: "CLI\\\\SYSTEM" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

