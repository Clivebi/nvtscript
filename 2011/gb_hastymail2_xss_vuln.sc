if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801576" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)" );
	script_cve_id( "CVE-2010-4646" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Hastymail2 'background' Attribute Cross-site scripting vulnerability" );
	script_xref( name: "URL", value: "http://www.hastymail.org/security/" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/01/05/3" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/01/06/14" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_hastymail2_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "hastymail2/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Hastymail2 version prior to 1.01." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of crafted background attribute
  within a cell in a TABLE element which allows remote attackers to inject arbitrary web script or HTML." );
	script_tag( name: "solution", value: "Upgrade to the Hastymail2 1.01 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running Hastymail2 and is prone to cross-site scripting
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
ver = get_kb_item( "www/" + port + "/Hastymail2" );
if(!ver){
	exit( 0 );
}
hm2Ver = eregmatch( pattern: "^(.+) under (/.*)$", string: ver );
if(hm2Ver[1]){
	ver = ereg_replace( pattern: "([A-Za-z]+)", replace: "0.", string: hm2Ver[1] );
	if(ver != NULL){
		if(version_is_less( version: ver, test_version: "1.01" )){
			report = report_fixed_ver( installed_version: ver, fixed_version: "1.01" );
			security_message( port: port, data: report );
		}
	}
}

