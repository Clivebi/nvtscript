CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106996" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-28 10:39:33 +0700 (Fri, 28 Jul 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-24 01:29:00 +0000 (Tue, 24 Oct 2017)" );
	script_cve_id( "CVE-2016-9042", "CVE-2017-6460" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Palo Alto PAN-OS NTP Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	script_tag( name: "summary", value: "The Network Time Protocol (NTP) library has been found to contains two
vulnerabilities CVE-2016-9042 and CVE-2017-6460. Palo Alto Networks software makes use of the vulnerable library
and may be affected. This issue only affects the management plane of the firewall." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PAN-OS 6.1, PAN-OS 7.0, PAN-OS 7.1, PAN-OS 8.0.3 and earlier." );
	script_tag( name: "solution", value: "Update to PAN-OS 7.0.18 or later, PAN-OS 7.1.12 or later, PAN-OS 8.0.4 or
later." );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/92" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_is_less( version: version, test_version: "7.0.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.18" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.1", test_version2: "7.1.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.12" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.4" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

