CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105564" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 11961 $" );
	script_cve_id( "CVE-2016-3656" );
	script_name( "Palo Alto PAN-OS PAN-SA-2016-0004" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/37" );
	script_tag( name: "summary", value: "When a PAN-OS device is configured as a GlobalProtect web portal, a specially crafted request to the portal could result in a crash of the service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS releases 5.0.18 and newer, 6.0.13 and newer, 6.1.10 and newer, 7.0.5H2 and newer" );
	script_tag( name: "impact", value: "This issue can be exploited remotely by an attacker with network access to the GlobalProtect portal in order to cause a denial-of-service (DoS) via a service crash." );
	script_tag( name: "affected", value: "PAN-OS releases 5.0.17 and prior, 6.0.12 and prior, 6.1.9 and prior, 7.0.5 and prior" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-03-07 14:20:25 +0100 (Mon, 07 Mar 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
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
	fix = "7.0.5H2";
}
if(version == "7.0.5"){
	hotfix = get_kb_item( "palo_alto_pan_os/hotfix" );
	if(!hotfix || int( hotfix ) < int( 2 )){
		fix = "7.0.5H2";
	}
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

