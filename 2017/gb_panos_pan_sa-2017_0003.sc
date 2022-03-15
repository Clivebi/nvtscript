CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140175" );
	script_cve_id( "CVE-2016-5195" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_name( "Palo Alto PAN-OS Kernel Vulnerability" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/73" );
	script_tag( name: "summary", value: "A vulnerability exists in the kernel of PAN-OS that may result in an elevation of privilege. This issue is publicly known as Dirty COW." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS 7.1.8 or later" );
	script_tag( name: "affected", value: "PAN-OS 5.1, PAN-OS 6.0, PAN-OS 6.1, PAN-OS 7.0, PAN-OS 7.1.7 and earlier" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-17 16:15:00 +0000 (Mon, 17 Feb 2020)" );
	script_tag( name: "creation_date", value: "2017-02-22 16:10:55 +0100 (Wed, 22 Feb 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_is_less( version: version, test_version: "7.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.8" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

