CPE = "cpe:/a:hp:openview_network_node_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902076" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_cve_id( "CVE-2010-1964", "CVE-2010-1961", "CVE-2010-1960", "CVE-2010-3285" );
	script_bugtraq_id( 40873, 40637, 40638 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)" );
	script_name( "HP OpenView Network Node Manager Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_openview_nnm_detect.sc" );
	script_require_ports( "Services/www", 7510 );
	script_mandatory_keys( "HP/OVNNM/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40101" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59250" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/59249" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2010/Jun/152" );
	script_xref( name: "URL", value: "http://marc.info/?l=bugtraq&m=128525454219838&w=2" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2010/Jun/1024071.html" );
	script_xref( name: "URL", value: "http://support.openview.hp.com/selfsolve/patches" );
	script_tag( name: "summary", value: "This host is running HP OpenView Network Node Manager and
  is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The flaws are due to boundary errors,

  - when creating an error message within 'ovwebsnmpsrv.exe'

  - within 'getProxiedStorageAddress()' in 'ovutil.dll'

  - when parsing command line argument variables within 'ovwebsnmpsrv.ex'
  And an unspecified vulnerability allows remote attackers to cause a denial
  of service via unknown vectors." );
	script_tag( name: "affected", value: "HP OpenView Network Node Manager version 7.51 and 7.53" );
	script_tag( name: "solution", value: "Apply the patch for OpenView NNM version 7.53." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a buffer overflow
  via a specially crafted HTTP request to the 'jovgraph.exe' CGI program." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_version( cpe: CPE, port: port );
if(!vers = get_kb_item( "www/" + port + "/HP/OVNNM/Ver" )){
	exit( 0 );
}
if(version_is_equal( version: vers, test_version: "B.07.51" ) || version_is_equal( version: vers, test_version: "B.07.53" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

