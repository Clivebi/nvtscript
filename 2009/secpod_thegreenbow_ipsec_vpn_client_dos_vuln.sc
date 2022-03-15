if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900922" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2918" );
	script_name( "TheGreenBow IPSec VPN Client Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36332/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2294" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/505816/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_thegreenbow_ipsec_vpn_client_detect.sc" );
	script_mandatory_keys( "TheGreenBow-IPSec-VPN-Client/Ver" );
	script_tag( name: "impact", value: "Attackers can exploit this issue via crafted requests to
x80000034 IOCTL probably involving an input or output buffer size of 0 to cause
denial of service." );
	script_tag( name: "affected", value: "TheGreenBow IPSec VPN Client version 4.61.003 and prior on
Windows." );
	script_tag( name: "insight", value: "The flaw is due to a NULL-pointer dereference error in
'tgbvpn.sys' driver when processing x80000034 IOCTLs." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has TheGreenBow IPSec VPN Client installed and is
prone to Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vpnPort = 500;
if(!get_udp_port_state( vpnPort )){
	exit( 0 );
}
vpnVer = get_kb_item( "TheGreenBow-IPSec-VPN-Client/Ver" );
if(!vpnVer){
	exit( 0 );
}
if(version_is_less_equal( version: vpnVer, test_version: "4.6.1.3" )){
	security_message( port: vpnPort, proto: "udp" );
}

