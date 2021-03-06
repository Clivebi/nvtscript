if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103724" );
	script_bugtraq_id( 60168, 60165 );
	script_cve_id( "CVE-2013-3634", "CVE-2013-3633" );
	script_tag( name: "cvss_base", value: "8.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:C" );
	script_version( "2019-06-06T07:39:31+0000" );
	script_name( "Siemens Scalance X200 Series Switches Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60165" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60168" );
	script_xref( name: "URL", value: "http://subscriber.communications.siemens.com/" );
	script_xref( name: "URL", value: "http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-170686.pdf" );
	script_tag( name: "last_modification", value: "2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)" );
	script_tag( name: "creation_date", value: "2013-05-30 17:50:28 +0200 (Thu, 30 May 2013)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( 23 );
	script_mandatory_keys( "telnet/siemens/scalance_x200/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Siemens Scalance X200 series switches are prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  1. a remote security bypass vulnerability.

  An attacker can exploit this issue to bypass certain security
  restrictions and execute SNMP commands without proper credentials.

  2. a remote privilege-escalation vulnerability.

  An attacker can exploit this issue to gain elevated privileges
  within the application and execute commands with escalated privileges." );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = 23;
if(!get_port_state( port )){
	exit( 0 );
}
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "SCALANCE X200" ) || !ContainsString( banner, "Device type" ) || !ContainsString( banner, "Firmware" )){
	exit( 0 );
}
dv = eregmatch( pattern: NASLString( "Device type.*:.*SCALANCE ([^\\r\\n ]+)" ), string: banner );
if(isnull( dv[1] )){
	exit( 0 );
}
device = dv[1];
vuln_devices = make_list( "X204",
	 "X202-2",
	 "X201-3",
	 "X200-4" );
for vd in vuln_devices {
	if(vd == device){
		affected_device = TRUE;
		break;
	}
}
if(!affected_device){
	exit( 0 );
}
fw = eregmatch( pattern: NASLString( "Firmware.*: V ([^\\r\\n ]+)" ), string: banner );
if(isnull( fw[1] )){
	exit( 0 );
}
firmware = fw[1];
if(version_is_less( version: firmware, test_version: "5.1.0" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

