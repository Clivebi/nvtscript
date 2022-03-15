if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810980" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_cve_id( "CVE-2017-5135" );
	script_bugtraq_id( 98092 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-19 17:59:31 +0530 (Fri, 19 May 2017)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "Technicolor DPC3928SL SNMP Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host has Technicolor DPC3928SL device
  and is prone to snmp authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted SNMP authentication request
  and check whether it is able to bypass authentication or not." );
	script_tag( name: "insight", value: "The flaw is due to the value placed in the
  community string field is not handled properly by the snmp agent in different
  devices (usually cable modems)." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to bypass certain security restrictions and perform unauthorized
  actions like write in the MIB etc." );
	script_tag( name: "affected", value: "Technicolor DPC3928SL firmware version
  D3928SL-P15-13-A386-c3420r55105-160127a is vulnerable, other devices are also
  affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://stringbleed.github.io" );
	script_xref( name: "URL", value: "https://www.reddit.com/r/netsec/comments/67qt6u/cve_20175135_snmp_authentication_bypass" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "snmp_detect.sc", "gb_default_credentials_options.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("snmp_func.inc.sc");
require("misc_func.inc.sc");
snmp_port = snmp_get_port( default: 161 );
if(get_kb_item( "SNMP/" + snmp_port + "/v12c/all_communities" )){
	exit( 0 );
}
vt_strings = get_vt_strings();
community = vt_strings["default"];
if(ret = snmp_get( port: snmp_port, oid: "1.3.6.1.2.1.1.1.0", version: 2, community: community )){
	report = "Result of the system description query with the community '" + community + "':\\n\\n" + ret + "\\n";
	security_message( port: snmp_port, data: report, proto: "udp" );
	exit( 0 );
}
exit( 99 );

