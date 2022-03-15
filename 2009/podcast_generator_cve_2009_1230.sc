if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100135" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_bugtraq_id( 34317 );
	script_cve_id( "CVE-2009-1230" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Podcast Generator 'core/admin/delete.php' Arbitrary File Deletion Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "podcast_generator_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "podcast_generator/detected" );
	script_tag( name: "solution", value: "The vendor has released an update. Please see the references for more information." );
	script_tag( name: "summary", value: "Podcast Generator is prone to a vulnerability that lets attackers
  delete arbitrary files on the affected computer in the context of
  the webserver." );
	script_tag( name: "impact", value: "Successful attacks may aid in launching further attacks." );
	script_tag( name: "affected", value: "Podcast Generator 1.1 is vulnerable, prior versions may also be
  affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34317" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/podcast_generator" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_less( version: vers, test_version: "1.2" )){
		security_message( port: port, data: "The target host was found to be vulnerable." );
		exit( 0 );
	}
}
exit( 99 );

