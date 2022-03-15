CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106826" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-23 15:33:39 +0700 (Tue, 23 May 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_cve_id( "CVE-2016-5696" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Palo Alto PAN-OS Kernel Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	script_tag( name: "summary", value: "A vulnerability exists in the kernel of PAN-OS that may result in
Information Disclosure." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The challenge ACK rate limiting in the kernel's networking subsystem may
allow an off-path attacker to leak certain information about a given connection by creating congestion on the
global challenge ACK rate limit counter and then measuring the changes by probing packets." );
	script_tag( name: "affected", value: "PAN-OS 6.1, PAN-OS 7.0.15 and earlier, PAN-OS 7.1.9 and earlier." );
	script_tag( name: "solution", value: "Update to PAN-OS 7.0.16, 7.1.10 or later." );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/85" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_is_less( version: version, test_version: "7.0.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.16" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.1\\." )){
	if(version_is_less( version: version, test_version: "7.1.10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.1.10" );
		if(model){
			report += "\nModel:             " + model;
		}
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

