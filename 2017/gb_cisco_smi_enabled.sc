if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140162" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-02-16 11:39:34 +0100 (Thu, 16 Feb 2017)" );
	script_name( "Cisco Smart Install Protocol Misuse" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_smi_detect.sc" );
	script_mandatory_keys( "cisco/smi/detected" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20170214-smi" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/540130" );
	script_xref( name: "URL", value: "https://2016.zeronights.ru/wp-content/uploads/2016/12/CiscoSmartInstall.v3.pdf" );
	script_xref( name: "URL", value: "http://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html#23355" );
	script_tag( name: "summary", value: "Several researchers have reported on the use of Smart Install (SMI) protocol messages toward Smart Install clients,
  also known as integrated branch clients (IBC), allowing an unauthenticated, remote attacker to change the startup-config file and force a reload of the
  device, load a new IOS image on the device, and execute high-privilege CLI commands on switches running Cisco IOS and IOS XE Software.

  Cisco does not consider this a vulnerability in Cisco IOS, IOS XE, or the Smart Install feature itself but a misuse of the Smart Install protocol, which
  does not require authentication by design. Customers who are seeking more than zero-touch deployment should consider deploying the Cisco Network Plug and
  Play solution instead." );
	script_tag( name: "solution", value: "Cisco has updated the Smart Install Configuration Guide to include security best practices regarding the deployment of
  the Cisco Smart Install feature within customer infrastructures." );
	script_tag( name: "qod", value: "75" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(!port = service_get_port( proto: "cisco_smi", nodefault: TRUE )){
	exit( 0 );
}
report = "The Cisco Smart Install Protocol was detected on the target host.";
security_message( data: report, port: port );
exit( 0 );

