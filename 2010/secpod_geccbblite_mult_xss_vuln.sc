if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900747" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4649" );
	script_bugtraq_id( 35449 );
	script_name( "geccBBlite Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/56278" );
	script_xref( name: "URL", value: "http://groups.csail.mit.edu/pag/ardilla/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_geccbblite_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "geccbblite/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject arbitrary web
  script or HTML in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "geccBBlite version 0.1 and prior." );
	script_tag( name: "insight", value: "Flaws are caused by improper validation of user-supplied input in multiple
  scripts. This can be exploited using the 'postatoda' parameter to inject
  malicious script into a Web page." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to geccBBlite version 0.2 or later." );
	script_tag( name: "summary", value: "The host is running geccBBlite and is prone to multiple Cross-Site
  Scripting vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
gbbPort = http_get_port( default: 80 );
gcbbVer = get_kb_item( "www/" + gbbPort + "/geccBBlite" );
if(isnull( gcbbVer )){
	exit( 0 );
}
gcbbVer = eregmatch( pattern: "^(.+) under (/.*)$", string: gcbbVer );
if(gcbbVer[1] != NULL){
	if(version_is_less_equal( version: gcbbVer[1], test_version: "1.0" )){
		report = report_fixed_ver( installed_version: gcbbVer[1], vulnerable_range: "Less than or equal to 1.0" );
		security_message( port: gbbPort, data: report );
	}
}

