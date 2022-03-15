if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103815" );
	script_bugtraq_id( 62858 );
	script_cve_id( "CVE-2012-4098" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "2021-02-01T10:40:13+0000" );
	script_name( "Cisco NX-OS Border Gateway Protocol Component Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62858" );
	script_xref( name: "URL", value: "http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtn13055" );
	script_tag( name: "last_modification", value: "2021-02-01 10:40:13 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2013-10-18 10:24:45 +0200 (Fri, 18 Oct 2013)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause the BGP service to reset
  and resync, denying service to legitimate users." );
	script_tag( name: "vuldetect", value: "Check the NX OS version." );
	script_tag( name: "insight", value: "This issue is being tracked by Cisco bug ID CSCtn13055." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Cisco NX-OS is prone to a denial-of-service vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "Cisco Nexus 7000 Series running on NX-OS." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
if(!nx_model = get_kb_item( "cisco_nx_os/model" )){
	exit( 0 );
}
if(!nx_ver = get_kb_item( "cisco_nx_os/version" )){
	exit( 0 );
}
if(!IsMatchRegexp( nx_model, "^7" )){
	exit( 0 );
}
first_found = "5.2.0.180.S14";
fixed = "5.2.0.218.S0";
vers = ereg_replace( pattern: "[()]", replace: ".", string: nx_ver );
if(revcomp( a: vers, b: first_found ) >= 0){
	report = report_fixed_ver( installed_version: nx_ver, fixed_version: "5.2(0.218)S0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

