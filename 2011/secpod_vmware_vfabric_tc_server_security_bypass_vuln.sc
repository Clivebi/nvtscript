if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902565" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-31 13:40:07 +0200 (Wed, 31 Aug 2011)" );
	script_bugtraq_id( 49122 );
	script_cve_id( "CVE-2011-0527" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "VMware vFabric tc Server JMX Authentication Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025923" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/69156" );
	script_xref( name: "URL", value: "http://www.springsource.com/security/cve-2011-0527" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "secpod_vmware_springsource_tc_server_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "vmware/tc_server/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to bypass certain security
  restrictions and gain unauthorized access, which may lead to further attacks." );
	script_tag( name: "affected", value: "vFabric tc Server versions 2.0.0 through 2.0.5.SR01
  vFabric tc Server versions 2.1.0 through 2.1.1.SR01" );
	script_tag( name: "insight", value: "The flaw is caused by the storing of passwords for JMX authentication in an
  obfuscated form, which makes it easier for context-dependent attackers to
  obtain access by leveraging an ability to read stored passwords." );
	script_tag( name: "solution", value: "Upgrade to vFabric tc Server version 2.0.6.RELEASE or 2.1.2.RELEASE." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running VMware vFabric tc Server and is prone to
  security bypass vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 8080 );
sstcVer = get_kb_item( NASLString( "www/", port, "Vmaware/SSTC/Runtime" ) );
if(isnull( sstcVer )){
	exit( 0 );
}
sstcVer = eregmatch( pattern: "^(.+) under (/.*)$", string: sstcVer );
if(isnull( sstcVer[1] )){
	exit( 0 );
}
if(version_in_range( version: sstcVer[1], test_version: "2.0.0", test_version2: "2.0.5.SR01" ) || version_in_range( version: sstcVer[1], test_version: "2.1.0", test_version2: "2.1.1.SR01" )){
	security_message( port );
}

