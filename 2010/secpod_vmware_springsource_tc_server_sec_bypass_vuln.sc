if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902188" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_cve_id( "CVE-2010-1454" );
	script_bugtraq_id( 40205 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "SpringSource tc Server 'JMX' Interface Security Bypass Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_vmware_springsource_tc_server_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "vmware/tc_server/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain JMX interface access
  via a blank password." );
	script_tag( name: "affected", value: "VMware SpringSource tc Server Runtime 6.0.19 and 6.0.20 before 6.0.20.D and
  6.0.25.A before 6.0.25.A-SR01." );
	script_tag( name: "insight", value: "The flaw is cused due to error in,
  'com.springsource.tcserver.serviceability.rmi.JmxSocketListener', if the
  listener is configured to use an encrypted password then entering either the
  correct password or an empty string will allow authenticated access to the
  JMX interface." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to SpringSource tc Server Runtime to 6.0.20.D or 6.0.25.A-SR01." );
	script_tag( name: "summary", value: "This host is running SpringSource tc Server and is prone to security
  bypass vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39778" );
	script_xref( name: "URL", value: "http://www.springsource.com/security/cve-2010-1454" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
sstcPort = http_get_port( default: 8080 );
sstcVer = get_kb_item( NASLString( "www/", sstcPort, "/Vmware/SSTC/Runtime" ) );
if(isnull( sstcVer )){
	exit( 0 );
}
sstcVer = eregmatch( pattern: "^(.+) under (/.*)$", string: sstcVer );
if(isnull( sstcVer[1] )){
	exit( 0 );
}
if(version_is_equal( version: sstcVer[1], test_version: "6.0.19" ) || version_in_range( version: sstcVer[1], test_version: "6.0.20", test_version2: "6.0.20.C" ) || version_in_range( version: sstcVer[1], test_version: "6.0.25", test_version2: "6.0.25.A.SR00" )){
	security_message( sstcPort );
}

