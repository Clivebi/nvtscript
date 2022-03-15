CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105562" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-3657" );
	script_name( "Palo Alto PAN-OS PAN-SA-2016-0005" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/38" );
	script_tag( name: "summary", value: "When a PAN-OS device is configured as a GlobalProtect portal, a vulnerability exists where an improper handling of a buffer involved in the processing of SSL VPN requests can result in device crash and possible remote code execution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS releases 5.0.18, 6.0.13, 6.1.10 and 7.0.5 and newer" );
	script_tag( name: "impact", value: "An attacker with network access to the vulnerable GlobalProtect portal may be able to perform a denial-of-service (DoS) attack on the device, and may be able to perform remote code execution on the affected device." );
	script_tag( name: "affected", value: "PAN-OS releases 5.0.17, 6.0.12, 6.1.9, 7.0.4 and prior" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-17 16:15:00 +0000 (Mon, 17 Feb 2020)" );
	script_tag( name: "creation_date", value: "2016-02-25 11:50:51 +0100 (Thu, 25 Feb 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.0.17" )){
	fix = "5.0.18";
}
if(version_in_range( version: version, test_version: "6.0", test_version2: "6.0.12" )){
	fix = "6.0.13";
}
if(version_in_range( version: version, test_version: "6.1", test_version2: "6.1.9" )){
	fix = "6.1.10";
}
if(version_in_range( version: version, test_version: "7.0", test_version2: "7.0.4" )){
	fix = "7.0.5";
}
if(fix){
	report = "Installed version: " + version + "\n" + "Fixed version:     " + fix;
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

