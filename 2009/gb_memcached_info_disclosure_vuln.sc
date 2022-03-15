CPE = "cpe:/a:memcached:memcached";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800715" );
	script_version( "2021-04-14T13:21:59+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 13:21:59 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-1255", "CVE-2009-1494" );
	script_bugtraq_id( 34756 );
	script_name( "Memcached < 1.2.8 Information Disclosure Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_memcached_detect.sc", "gb_memcached_detect_udp.sc" );
	script_mandatory_keys( "memcached/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34915" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1196" );
	script_xref( name: "URL", value: "http://www.positronsecurity.com/advisories/2009-001.html" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker craft malicious
  commands and pass it to the vulnerable functions to gain sensitive information about the
  application i.e. disclosure of locations of memory regions and defeat ASLR protections, by sending
  a command to the daemon's TCP port." );
	script_tag( name: "affected", value: "Memcached version prior to 1.2.8." );
	script_tag( name: "insight", value: "- Error in process_stat function discloses the contents of
  /proc/self/maps in response to a stats maps command.

  - Error in process_stat function which discloses memory allocation statistics in response to a
  stats malloc command." );
	script_tag( name: "solution", value: "Update to version 1.2.8 or later." );
	script_tag( name: "summary", value: "Memcached is prone to multiple information disclosure
  vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
vers = infos["version"];
proto = infos["proto"];
if(version_is_less( version: vers, test_version: "1.2.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.2.8" );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

