CPE = "cpe:/a:znc:znc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108604" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-17 06:47:14 +0000 (Mon, 17 Jun 2019)" );
	script_cve_id( "CVE-2019-9917" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-15 03:29:00 +0000 (Sat, 15 Jun 2019)" );
	script_name( "ZNC < 1.7.3-rc1 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_znc_consolidation.sc" );
	script_mandatory_keys( "znc/detected" );
	script_xref( name: "URL", value: "https://wiki.znc.in/ChangeLog/1.7.3" );
	script_xref( name: "URL", value: "https://github.com/znc/znc/commit/64613bc8b6b4adf1e32231f9844d99cd512b8973" );
	script_tag( name: "summary", value: "The host is running an ZNC IRC bouncer which is prone to a
  Denial of Service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation allows an existing remote user to cause a Denial of Service (crash)." );
	script_tag( name: "affected", value: "ZNC before 1.7.3-rc1." );
	script_tag( name: "solution", value: "Upgrade to ZNC 1.7.3-rc1 or later. Please see the references for more information." );
	script_tag( name: "insight", value: "The flaw can be triggered by an attacker by using an invalid encoding." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "1.7.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.7.3-rc1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

