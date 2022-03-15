CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106849" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-07 09:16:47 +0700 (Wed, 07 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_cve_id( "CVE-2016-8610" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Palo Alto PAN-OS OpenSSL Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	script_tag( name: "summary", value: "The OpenSSL library has been found to contain a vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Palo Alto Networks software makes use of the vulnerable library and may be
affected." );
	script_tag( name: "affected", value: "PAN-OS 6.1.17 and prior, PAN-OS 7.0.15 and prior, PAN-OS 7.1.10 and
prior." );
	script_tag( name: "solution", value: "Update to PAN-OS 6.1.18, 7.0.16, PAN-OS 7.1.11 or later." );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/87" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_is_less( version: version, test_version: "6.1.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1.18" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.0\\." )){
	if(version_is_less( version: version, test_version: "7.0.16" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.0.16" );
		if(model){
			report += "\nModel:             " + model;
		}
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^7\\.1\\." )){
	if(version_is_less( version: version, test_version: "7.1.11" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.1.11" );
		if(model){
			report += "\nModel:             " + model;
		}
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

