CPE = "cpe:/a:aerospike:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140132" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-27 14:35:35 +0100 (Fri, 27 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-28 02:59:00 +0000 (Sat, 28 Jan 2017)" );
	script_cve_id( "CVE-2016-9050", "CVE-2016-9054", "CVE-2016-9052", "CVE-2016-9049", "CVE-2016-9051", "CVE-2016-9053" );
	script_bugtraq_id( 95415, 95419, 95421 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Aerospike Database Server <= 3.10.0.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_aerospike_consolidation.sc" );
	script_mandatory_keys( "aerospike/detected" );
	script_tag( name: "summary", value: "Aerospike Database Server is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Ask the vendor for an update." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Denial of service in the fabric-worker component (CVE-2016-9049)

  - Information disclosure (CVE-2016-9050)

  - Out-of-bound write in the batch transaction field parsing functionality (CVE-2016-9051)

  - Multiple stacked based buffer overflows (CVE-2016-9052, CVE-2016-9054)

  - Out-of-bounds indexing (CVE-2016-9053)" );
	script_tag( name: "affected", value: "Aerospike Database Server versions up to 3.10.0.3 are known to be affected.
  Other versions might be affected as well." );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0264/" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0263/" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0265/" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0267/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "3.10.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Ask vendor" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

