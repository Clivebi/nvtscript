if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100491" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-02-09 12:21:13 +0100 (Tue, 09 Feb 2010)" );
	script_bugtraq_id( 38135 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "httpdx 'USER' Command Remote Format String Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38135" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/httpdx/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_httpdx_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "httpdx/installed" );
	script_tag( name: "summary", value: "The 'httpdx' program is prone to a remote format-string vulnerability." );
	script_tag( name: "impact", value: "An attacker may exploit this issue to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "The issue affects httpdx 1.5.2. Other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
httpdxPort = http_get_port( default: 80 );
httpdxVer = get_kb_item( "httpdx/" + httpdxPort + "/Ver" );
if(!isnull( httpdxVer )){
	if(version_is_equal( version: httpdxVer, test_version: "1.5.2" )){
		security_message( httpdxPort );
	}
}

