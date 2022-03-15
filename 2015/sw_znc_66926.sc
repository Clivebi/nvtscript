CPE = "cpe:/a:znc:znc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111033" );
	script_version( "2020-06-16T12:34:04+0000" );
	script_tag( name: "last_modification", value: "2020-06-16 12:34:04 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-08-29 12:00:00 +0200 (Sat, 29 Aug 2015)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2014-9403" );
	script_bugtraq_id( 66926 );
	script_name( "ZNC < 1.4 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "gb_znc_consolidation.sc" );
	script_mandatory_keys( "znc/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/66926" );
	script_tag( name: "summary", value: "ZNC is prone to a denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to crash the application,
  denying service to legitimate users." );
	script_tag( name: "affected", value: "ZNC 1.2 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "1.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

