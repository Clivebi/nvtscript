if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100467" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-1596" );
	script_bugtraq_id( 37949 );
	script_name( "Support Incident Tracker Blank Password Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37949" );
	script_xref( name: "URL", value: "http://sitracker.org/wiki/ReleaseNotes351" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "support_incident_tracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sit/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "The vendor has released an update. Please see the references for more
  information." );
	script_tag( name: "summary", value: "Support Incident Tracker (SiT!) is prone to an authentication-bypass
  vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to gain unauthorized access to the
  affected application." );
	script_tag( name: "affected", value: "Versions prior to Support Incident Tracker (SiT!) 3.51 are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/support_incident_tracker" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_less( version: vers, test_version: "3.51" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

