if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113454" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-08 13:03:19 +0000 (Thu, 08 Aug 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:07:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-5020" );
	script_name( "Yara <= 3.8.1 Denial of Service (DoS) Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_yara_ssh_detect.sc" );
	script_mandatory_keys( "yara/detected" );
	script_tag( name: "summary", value: "Yara is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists within the object lookup functionality.
  A specially crafted binary file can cause a negative value to be read
  to satisfy an assert, resulting in Denial of Service. An attacker can
  create a malicious binary to trigger this vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the application." );
	script_tag( name: "affected", value: "Yara through version 3.8.1." );
	script_tag( name: "solution", value: "Update to version 3.9.0." );
	script_xref( name: "URL", value: "https://talosintelligence.com/vulnerability_reports/TALOS-2019-0781" );
	exit( 0 );
}
CPE = "cpe:/a:virustotal:yara";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.9.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.0" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

