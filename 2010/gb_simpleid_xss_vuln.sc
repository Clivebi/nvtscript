if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801416" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4972" );
	script_name( "SimpleID 'index.php' Cross Site Scripting Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_simpleid_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "simpleid/detected" );
	script_tag( name: "insight", value: "Input passed via the 's' parameter to 'index.php' is not properly sanitised
  before being returned to the user." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to SimpleID version 0.6.5 or later." );
	script_tag( name: "summary", value: "This host is running SimpleID and is prone to cross site scripting
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "SimpleID version prior to 0.6.5" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
simidPort = http_get_port( default: 80 );
simidVer = get_version_from_kb( port: simidPort, app: "SimpleID/Ver" );
if(simidVer != NULL){
	if(version_is_less( version: simidVer, test_version: "0.6.5" )){
		report = report_fixed_ver( installed_version: simidVer, fixed_version: "0.6.5" );
		security_message( port: simidPort, data: report );
	}
}

