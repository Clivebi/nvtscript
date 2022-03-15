if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902570" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_bugtraq_id( 49621 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Colasoft Capsa Malformed SNMP V1 Packet Remote Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46034" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519630" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2011-09/0088.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to crash
the affected application, denying service to legitimate users." );
	script_tag( name: "affected", value: "Colasoft Capsa Version 7.2.1 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error within the SNMPv1
protocol dissector and can be exploited to cause a crash via a specially
crafted packet." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Colasoft Capsa and is prone to denial
of service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Colasoft\\Colasoft Capsa 7 Enterprise Demo Edition";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
version = registry_get_sz( key: key, item: "Version" );
if(version){
	if(version_is_less_equal( version: version, test_version: "7.2.1.2299" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

