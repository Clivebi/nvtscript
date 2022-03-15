CPE = "cpe:/a:kaspersky:kaspersky_total_security";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810513" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2016-4329", "CVE-2016-4305", "CVE-2016-4306", "CVE-2016-4307", "CVE-2016-4304" );
	script_bugtraq_id( 92771, 92639, 92657, 92683 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-11 02:59:00 +0000 (Wed, 11 Jan 2017)" );
	script_tag( name: "creation_date", value: "2017-01-23 14:29:52 +0530 (Mon, 23 Jan 2017)" );
	script_name( "Kaspersky Total Security Multiple DoS And Information Disclosure Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with Kaspersky
  Total Security is prone to multiple denial of service and information disclosure
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the 'syscall filtering' functionality of 'KLIF driver'.

  - An error in the 'IOCTL handling' functionality 'KL1 driver'.

  - An error in various 'IOCTL handlers' of the 'KLDISK driver'. Specially crafted
    IOCTL requests can cause the driver to return out-of-bounds kernel memory.

  - An error in 'window broadcast message handling' functionality." );
	script_tag( name: "impact", value: "Successful exploitation would allow remote
  attackers to cause application termination, bypass protection mechanism and
  obtain sensitive information." );
	script_tag( name: "affected", value: "Kaspersky Total Security version 16.0.0.614" );
	script_tag( name: "solution", value: "Upgrade to Kaspersky Total Security version
  17.0.0.611 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.kaspersky.com/vulnerability.aspx?el=12430#250816_1" );
	script_xref( name: "URL", value: "http://usa.kaspersky.com/downloads" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1036702" );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0175" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_kaspersky_av_detect.sc" );
	script_mandatory_keys( "Kaspersky/TotNetSec/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!kasVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: kasVer, test_version: "16.0.0.614" )){
	report = report_fixed_ver( installed_version: kasVer, fixed_version: "17.0.0.611" );
	security_message( data: report );
	exit( 0 );
}

