if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11517" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2002-1661" );
	script_bugtraq_id( 6490 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Leafnode denials of service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "General" );
	script_dependencies( "nntpserver_detect.sc" );
	script_require_ports( "Services/nntp", 119 );
	script_mandatory_keys( "nntp/detected" );
	script_tag( name: "solution", value: "Update to version 1.9.48 or later." );
	script_tag( name: "summary", value: "According to its version number in the banner
  the Leafnode NNTP server is vulnerable to a denial of service." );
	script_tag( name: "impact", value: "The service may:

  - go into an infinite loop with 100% CPU use when an article that has been crossposted to
  several groups, one of which is the prefix of another, and when this article is then requested
  by its Message-ID.

  - hang without consuming CPU while waiting for data that never come." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("nntp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = nntp_get_port( default: 119 );
banner = get_kb_item( "nntp/banner/" + port );
if(!banner || !ContainsString( banner, "Leafnode" )){
	exit( 0 );
}
if(ereg( string: banner, pattern: "version +1\\.9\\.2[0-9]" ) || ereg( string: banner, pattern: "version +1\\.9\\.([3-9]|[1-3][0-9]|4[0-7])[^0-9]" ) || ereg( string: banner, pattern: "version +1\\.9\\.19" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

