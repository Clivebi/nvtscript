CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900167" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)" );
	script_bugtraq_id( 32088 );
	script_cve_id( "CVE-2008-4413" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "6.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:C/I:C/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_name( "HP SMH Unspecified Security Bypass Vulnerability" );
	script_dependencies( "secpod_hp_smh_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "HP/SMH/installed", "Host/runs_unixoide" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_xref( name: "URL", value: "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01586921" );
	script_tag( name: "impact", value: "Attackers can leverage this issue to gain local unauthorized access." );
	script_tag( name: "affected", value: "HP SMH version 2.2.6 and prior on HP-UX B.11.11 and B.11.23
  HP SMH version 2.2.6 and 2.2.8 and prior on HP-UX B.11.23 and B.11.31" );
	script_tag( name: "solution", value: "Update to HP SMH version 2.2.9.1 or subsequent." );
	script_tag( name: "summary", value: "The host is running System Management Homepage and is prone to
  local security bypass vulnerability." );
	script_tag( name: "insight", value: "The flaw is caused by an unspecified error, which can be exploited by
  local users to perform certain actions with escalated privileges." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("version_func.inc.sc");
if(os_host_runs( "hp-ux" ) != "yes"){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.2.9.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.9.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

