CPE = "cpe:/a:eggheads:eggdrop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100207" );
	script_version( "2021-04-20T08:49:45+0000" );
	script_tag( name: "last_modification", value: "2021-04-20 08:49:45 +0000 (Tue, 20 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)" );
	script_cve_id( "CVE-2009-1789" );
	script_bugtraq_id( 34985 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Eggdrop < 1.6.19+ctcpfix Remote DoS Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "eggdrop_detect.sc" );
	script_mandatory_keys( "eggdrop/installed" );
	script_tag( name: "summary", value: "Eggdrop is prone to a remote denial of service (DoS)
  vulnerability because it fails to adequately validate user-supplied input." );
	script_tag( name: "insight", value: "This issue is related to the vulnerability described in BID 2407
  (Eggdrop Server Module Message Handling Remote Buffer Overflow Vulnerability)." );
	script_tag( name: "impact", value: "An attacker may exploit this issue to crash the application,
  resulting in a DoS condition." );
	script_tag( name: "affected", value: "Eggdrop prior to version 1.6.19+ctcpfix." );
	script_tag( name: "solution", value: "Update to version 1.6.19+ctcpfix or later." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34985" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.6.19+ctcpfix" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.19+ctcpfix" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

