if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103818" );
	script_bugtraq_id( 62446 );
	script_cve_id( "CVE-2013-1121" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:C" );
	script_version( "2021-02-01T10:40:13+0000" );
	script_name( "Cisco NX-OS Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62446" );
	script_xref( name: "URL", value: "http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCuf49554" );
	script_tag( name: "last_modification", value: "2021-02-01 10:40:13 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2013-10-22 17:24:45 +0200 (Tue, 22 Oct 2013)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause the affected device to reload,
  denying service to legitimate users." );
	script_tag( name: "vuldetect", value: "Check the NX OS version." );
	script_tag( name: "insight", value: "This issue is being tracked by Cisco bug ID CSCuf49554." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Cisco NX-OS is prone to a denial-of-service vulnerability." );
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
vers = ereg_replace( pattern: "[()]", replace: ".", string: nx_ver );
vers = ereg_replace( pattern: "\\.$", replace: "", string: vers );
ff = make_list( "5.2.1.N1.3",
	 "6.0.2.N2.1" );
fixed = "6.2.1.81.S0";
for first_found in ff {
	if(revcomp( a: vers, b: first_found ) >= 0){
		report = report_fixed_ver( installed_version: nx_ver, fixed_version: "6.2(1.81)S0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

