CPE = "cpe:/a:bea:weblogic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811244" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_cve_id( "CVE-2017-10137", "CVE-2017-5638", "CVE-2017-10147", "CVE-2017-10178", "CVE-2013-2027", "CVE-2017-10148", "CVE-2017-10063", "CVE-2017-10123", "CVE-2017-10352", "CVE-2017-10271", "CVE-2017-10152", "CVE-2017-10336", "CVE-2017-10334" );
	script_bugtraq_id( 96729, 99651, 99644, 78027, 99652, 99653, 101304, 101392 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-07-19 12:53:23 +0530 (Wed, 19 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle WebLogic Server Multiple Vulnerabilities (cpujul2017-3236622)" );
	script_tag( name: "summary", value: "Oracle WebLogic Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to some unspecified errors in the
  'Sample apps (Struts 2)', 'Core Components', 'Web Container', 'WLST'
  'Web Services', 'WLS-WebServices' and 'WLS Security' components of application." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "Oracle WebLogic Server versions 10.3.6.0, 12.1.3.0, 12.2.1.1 and 12.2.1.2." );
	script_tag( name: "solution", value: "See the referenced advisories for a solution." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_weblogic_consolidation.sc" );
	script_mandatory_keys( "oracle/weblogic/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
affected = make_list( "10.3.6.0.0",
	 "12.1.3.0.0",
	 "12.2.1.2.0",
	 "12.2.1.1.0" );
for af in affected {
	if(version == af){
		report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
		security_message( data: report, port: 0 );
		exit( 0 );
	}
}
exit( 99 );

