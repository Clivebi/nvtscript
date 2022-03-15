CPE = "cpe:/o:cisco:nx-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103800" );
	script_bugtraq_id( 59452, 59454, 59456 );
	script_cve_id( "CVE-2013-1178", "CVE-2013-1179", "CVE-2013-1180" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_name( "Multiple Cisco Products Multiple Remote Buffer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/59452" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/59454" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/59456" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-1178" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-1179" );
	script_xref( name: "URL", value: "http://cxsecurity.com/cveshow/CVE-2013-1180" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130424-nxosmulti" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-10-09 17:02:49 +0200 (Wed, 09 Oct 2013)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	script_tag( name: "impact", value: "An attacker can exploit these issues to execute arbitrary code with
  the elevated privileges. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There are multiple buffer overflows in:

  - the Cisco Discovery Protocol (CDP) implementation

  - the SNMP and License Manager implementations" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Multiple Cisco NX-OS-Based products are prone to multiple remote buffer-
  overflow vulnerabilities because they fail to perform adequate boundary-checks on user-supplied data." );
	script_tag( name: "affected", value: "These issues being tracked by Cisco Bug IDs CSCtu10630, CSCtu10551,
  CSCtu10550, CSCtw56581, CSCtu10548, CSCtu10544, and CSCuf61275." );
	exit( 0 );
}
require("host_details.inc.sc");
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
nx_model = get_kb_item( "cisco_nx_os/model" );
if(!IsMatchRegexp( nx_model, "^6" ) || ContainsString( nx_model, "3548" )){
	exit( 0 );
}
affected = make_list( "6.1",
	 "6.0(2)",
	 "6.0(1)",
	 "5.2(3a)",
	 "5.2(3)",
	 "5.2(1)",
	 "5.2",
	 "5.1(6)",
	 "5.1(5)",
	 "5.1(4)",
	 "5.1(3)n1(1a)",
	 "5.1(3)n1(1)",
	 "5.1(3)",
	 "5.1(2)",
	 "5.1(1a)",
	 "5.1(1)",
	 "5.1",
	 "5.0(5)",
	 "5.0(3)n2(2b)",
	 "5.0(3)n2(2a)",
	 "5.0(3)n2(2)",
	 "5.0(3)n2(1)",
	 "5.0(3)n1(1c)",
	 "5.0(3)n1(1b)",
	 "5.0(3)n1(1a)",
	 "5.0(3)n1(1)",
	 "5.0(3)",
	 "5.0(2a)",
	 "5.0(2)n2(1a)",
	 "5.0(2)n2(1)",
	 "5.0(2)n1(1)",
	 "5.0(2)",
	 "5.0",
	 "4.2.(2a)",
	 "4.2(8)",
	 "4.2(6)",
	 "4.2(4)",
	 "4.2(3)",
	 "4.2(2)",
	 "4.2(1)sv1(5.1)",
	 "4.2(1)sv1(4a)",
	 "4.2(1)sv1(4)",
	 "4.2(1)n2(1a)",
	 "4.2(1)n2(1)",
	 "4.2(1)n1(1)",
	 "4.2(1)",
	 "4.2",
	 "4.1.(5)",
	 "4.1.(4)",
	 "4.1.(3)",
	 "4.1.(2)",
	 "4.1(3)n2(1a)",
	 "4.1(3)n2(1)",
	 "4.1(3)n1(1a)",
	 "4.1(3)n1(1)",
	 "4.0(4)sv1(3d)",
	 "4.0(4)sv1(3c)",
	 "4.0(4)sv1(3b)",
	 "4.0(4)sv1(3a)",
	 "4.0(4)sv1(3)",
	 "4.0(4)sv1(2)",
	 "4.0(4)sv1(1)",
	 "4.0(1a)n2(1a)",
	 "4.0(1a)n2(1)",
	 "4.0(1a)n1(1a)",
	 "4.0(1a)n1(1)",
	 "4.0(0)n1(2a)",
	 "4.0(0)n1(2)",
	 "4.0(0)n1(1a)",
	 "4.0" );
if(!nx_ver = get_kb_item( "cisco_nx_os/version" )){
	exit( 0 );
}
for affected_nx_ver in affected {
	if(nx_ver == affected_nx_ver){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

