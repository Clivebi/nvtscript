CPE = "cpe:/o:greenbone:greenbone_os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107017" );
	script_cve_id( "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-06-21 11:11:07 +0200 (Fri, 21 Jun 2019)" );
	script_name( "Greenbone OS - Kernel Denial of Service Vulnerabilities - June 19" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gb_greenbone_os_consolidation.sc" );
	script_mandatory_keys( "greenbone/gos/detected" );
	script_tag( name: "summary", value: "The Kernel in Greenbone OS is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "insight", value: "Multiple TCP Selective Acknowledgement (SACK) and Maximum Segment Size (MSS)
  networking vulnerabilities may cause denial-of-service conditions in Linux kernels as used
  in Greenbone OS." );
	script_tag( name: "impact", value: "A remote attacker could use this to cause a denial of service or kernel failure (panic) by:

  - triggering an integer overflow (CVE-2019-11477)

  - sending a sequence of specifically crafted selective acknowledgements (SACK),
    that may cause a fragmented TCP queue (CVE-2019-11478)

  - making use of the default maximum segment size (MSS), which is hard-coded to 48 bytes.
    This may cause an increase of fragmented packets (CVE-2019-11479)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Greenbone OS 4.2.29, 4.3.14 or 5.0.3." );
	script_tag( name: "affected", value: "Greenbone OS prior to version 4.2.29, 4.3.14 or 5.0.3 respectively." );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/905115" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
version = str_replace( string: version, find: "-", replace: "." );
if(version_is_less( version: version, test_version: "4.2.29" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.29" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.3" )){
	if(version_is_less( version: version, test_version: "4.3.14" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.3.14" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^5\\.0" )){
	if(version_is_less( version: version, test_version: "5.0.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "5.0.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

