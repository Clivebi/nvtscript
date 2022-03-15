CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100810" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)" );
	script_bugtraq_id( 43269, 43208 );
	script_cve_id( "CVE-2010-3011", "CVE-2010-3009", "CVE-2010-3012" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43269" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43208" );
	script_xref( name: "URL", value: "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02512995&admit=109447626+1284637282234+28353475" );
	script_xref( name: "URL", value: "https://www.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02475053" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "HP System Management Homepage is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "1. An HTTP response-splitting vulnerability.

  Attackers can leverage this issue to influence or misrepresent how web
  content is served, cached, or interpreted. This could aid in various
  attacks that try to entice client users into a false sense of trust.

  2. An unspecified remote information-disclosure vulnerability.

  Remote attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks." );
	script_tag( name: "affected", value: "HP System Management Homepage versions prior to 6.2 are vulnerable." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.2.0.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.0.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

