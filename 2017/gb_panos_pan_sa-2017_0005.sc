CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140177" );
	script_cve_id( "CVE-2017-5583" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_name( "Palo Alto PAN-OS Detail Information Disclosure in the Management Web Interface" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/75" );
	script_tag( name: "summary", value: "PAN-OS contains a post-authentication vulnerability that may allow
  for Information Disclosure. Successful exploitation allows an attacker to download arbitrary files from a folder." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS 6.1.16 and later, PAN-OS 7.0.13 and later, PAN-OS 7.1.8 and later." );
	script_tag( name: "affected", value: "PAN-OS 6.1.15 and earlier, PAN-OS 7.0.12 and earlier, PAN-OS 7.1.7 and earlier." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
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
if( IsMatchRegexp( version, "^6\\.1" ) ) {
	fix = "6.1.16";
}
else {
	if( IsMatchRegexp( version, "^7\\.0" ) ) {
		fix = "7.0.13";
	}
	else {
		if(IsMatchRegexp( version, "^7\\.1" )){
			fix = "7.1.8";
		}
	}
}
if(!fix){
	exit( 0 );
}
if(version_is_less( version: version, test_version: fix )){
	report = "Installed version: " + version + "\n" + "Fixed version:     " + fix;
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

