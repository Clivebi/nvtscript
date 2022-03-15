if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100298" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-10 11:30:08 +0200 (Sat, 10 Oct 2009)" );
	script_bugtraq_id( 36519 );
	script_cve_id( "CVE-2009-3445" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Code-Crafters Ability Mail Server IMAP FETCH Request Remote Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "imap4_banner.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/codecrafters/ability/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/36519" );
	script_xref( name: "URL", value: "http://www.code-crafters.com/abilitymailserver/updatelog.html" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to cause the affected application to
  crash, denying service to legitimate users." );
	script_tag( name: "affected", value: "Versions prior to Ability Mail Server 2.70 are affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Ability Mail Server is prone to a denial-of-service vulnerability
  because it fails to adequately handle IMAP requests." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("imap_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = imap_get_port( default: 143 );
if(!banner = imap_get_banner( port: port )){
	exit( 0 );
}
if(!ContainsString( banner, "Code-Crafters" )){
	exit( 0 );
}
version = eregmatch( pattern: "Ability Mail Server ([0-9.]+)", string: banner );
if(isnull( version[1] )){
	exit( 0 );
}
if(version_is_less( version: version[1], test_version: "2.70" )){
	report = report_fixed_ver( installed_version: version[1], fixed_version: "2.70" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

