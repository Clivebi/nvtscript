if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106241" );
	script_version( "2020-03-26T08:48:45+0000" );
	script_tag( name: "last_modification", value: "2020-03-26 08:48:45 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-09-13 10:45:09 +0700 (Tue, 13 Sep 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-1473" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Small Business 220 Series Smart Plus Switches SNMP Unauthorized Access Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "snmp_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/detected" );
	script_tag( name: "summary", value: "A vulnerability in the implementation of SNMP functionality in Cisco
  Small Business 220 Series Smart Plus (Sx220) Switches could allow an unauthenticated, remote attacker to
  gain unauthorized access to SNMP objects on an affected device." );
	script_tag( name: "vuldetect", value: "Tries to get the SNMP system description with the default community." );
	script_tag( name: "insight", value: "The vulnerability is due to the presence of a default SNMP community
  string that is added during device installation and cannot be deleted. An attacker could exploit this
  vulnerability by using the default SNMP community string to access SNMP objects on an affected device." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to view and modify SNMP
  objects on a targeted device." );
	script_tag( name: "affected", value: "Cisco Small Business 220 Series Smart Plus (Sx220) Switches running
  firmware release 1.0.0.17, 1.0.0.18, or 1.0.0.19." );
	script_tag( name: "solution", value: "Upgrade to firmware release 1.0.1.1." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-sps3" );
	script_xref( name: "URL", value: "http://www.synacktiv.ninja/ressources/advisories_cisco_switch_sg220_default_snmp.pdf" );
	exit( 0 );
}
require("snmp_func.inc.sc");
port = snmp_get_port( default: 161 );
if(get_kb_item( "SNMP/" + port + "/v12c/all_communities" )){
	exit( 0 );
}
community = "rmonmgmtuicommunity";
if(res = snmp_get( port: port, oid: "1.3.6.1.2.1.1.1.0", version: 2, community: community )){
	report = "Result of the system description query with the community 'rmonmgmtuicommunity':\\n\\n" + res + "\\n";
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
exit( 99 );

