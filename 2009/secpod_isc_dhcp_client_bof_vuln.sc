if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900694" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0692" );
	script_bugtraq_id( 35668 );
	script_name( "ISC DHCP Client Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "https://www.isc.org/node/468" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35785" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/410676" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1891" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_isc_dhcp_client_detect.sc", "gather-package-list.sc" );
	script_mandatory_keys( "ISC/DHCP-Client/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to run arbitrary code, corrupt memory,
  and can cause denial of service." );
	script_tag( name: "affected", value: "ISC DHCP dhclient 4.1 before 4.1.0p1

  ISC DHCP dhclient 4.0 before 4.0.1p1

  ISC DHCP dhclient 3.1 before 3.1.2p1

  ISC DHCP dhclient all versions in 3.0

  and 2.0 series." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within the 'script_write_params()'
  function in 'client/dhclient.c' which can be exploited to cause a stack-based
  buffer overflow by sending an overly long subnet-mask option." );
	script_tag( name: "solution", value: "Upgrade to version 4.1.0p1, 4.0.1p1, or 3.1.2p1 or later." );
	script_tag( name: "summary", value: "This host has installed ISC DHCP Client and is prone to Buffer
  overflow Vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
release = get_kb_item( "ssh/login/release" );
if(release && release == "RHENT_5"){
	exit( 0 );
}
dhcpVer = get_kb_item( "ISC/DHCP-Client/Ver" );
if(!dhcpVer){
	exit( 0 );
}
if( IsMatchRegexp( dhcpVer, "^4\\.1" ) ){
	if(version_is_less( version: dhcpVer, test_version: "4.1.0.p1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}
else {
	if( IsMatchRegexp( dhcpVer, "^4\\.0" ) ){
		if(version_is_less( version: dhcpVer, test_version: "4.0.1.p1" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
		}
	}
	else {
		if( IsMatchRegexp( dhcpVer, "^3\\.1" ) ){
			if(version_is_less( version: dhcpVer, test_version: "3.1.2.p1" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
		else {
			if(( IsMatchRegexp( dhcpVer, "^3\\.0" ) ) || ( IsMatchRegexp( dhcpVer, "^2\\.0" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
			}
		}
	}
}

