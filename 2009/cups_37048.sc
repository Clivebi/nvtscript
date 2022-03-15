CPE = "cpe:/a:apple:cups";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100369" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)" );
	script_bugtraq_id( 37048 );
	script_cve_id( "CVE-2009-3553" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "CUPS File Descriptors Handling Remote Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "secpod_cups_detect.sc" );
	script_require_ports( "Services/www", 631 );
	script_mandatory_keys( "CUPS/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37048" );
	script_xref( name: "URL", value: "http://www.cups.org" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=530111" );
	script_tag( name: "impact", value: "A remote attacker can exploit this issue to crash the affected
  application, denying service to legitimate users." );
	script_tag( name: "affected", value: "This issue affects CUPS 1.3.7. Other versions may be vulnerable as
  well." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "CUPS is prone to a denial-of-service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!IsMatchRegexp( vers, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "1.3.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

