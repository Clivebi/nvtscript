if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105019" );
	script_bugtraq_id( 67214 );
	script_cve_id( "CVE-2014-0684" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:N/I:N/A:C" );
	script_version( "2021-02-01T10:40:13+0000" );
	script_name( "Cisco Nexus 7000 Series Switches Local Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/67214" );
	script_xref( name: "URL", value: "https://tools.cisco.com/bugsearch/bug/CSCui56136" );
	script_tag( name: "last_modification", value: "2021-02-01 10:40:13 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2014-05-06 11:19:57 +0200 (Tue, 06 May 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows attackers to cause denial-of-
  service conditions." );
	script_tag( name: "vuldetect", value: "Check the NX OS version." );
	script_tag( name: "insight", value: "This issue is being tracked by Cisco Bug ID CSCui56136." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Cisco Nexus 7000 Series switches running on NX-OS are prone to a local
  denial-of-service vulnerability." );
	script_tag( name: "affected", value: "Cisco Nexus 7000 Series switches running on NX-OS 6.2(2)S30." );
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
first_found = "6.2.2.S30";
fixed = "6.2.2.S33";
vers = ereg_replace( pattern: "[()]", replace: ".", string: nx_ver );
if(revcomp( a: vers, b: first_found ) >= 0){
	if(revcomp( a: fixed, b: vers ) > 0){
		report = report_fixed_ver( installed_version: nx_ver, fixed_version: "6.2(2)S33" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

