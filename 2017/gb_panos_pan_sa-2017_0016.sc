CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106827" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-23 15:33:39 +0700 (Tue, 23 May 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 14:43:00 +0000 (Wed, 05 May 2021)" );
	script_cve_id( "CVE-2016-4971" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Palo Alto PAN-OS WGET Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Palo Alto PAN-OS Local Security Checks" );
	script_dependencies( "gb_palo_alto_panOS_version.sc" );
	script_mandatory_keys( "palo_alto_pan_os/version" );
	script_tag( name: "summary", value: "The wget library has been found to contain a vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "wget allows remote servers to write to arbitrary files by redirecting a
request from HTTP to a crafted FTP resource. Palo Alto Networks software makes use of the vulnerable library and
may be affected." );
	script_tag( name: "affected", value: "PAN-OS 6.1.16 and earlier, PAN-OS 7.0.14 and earlier, PAN-OS 7.1.9 and
earlier, PAN-OS 8.0." );
	script_tag( name: "solution", value: "Update to PAN-OS 6.1.17, PAN-OS 7.0.15, PAN-OS 7.1.10, PAN-OS 8.0.1 or
later." );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/86" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
model = get_kb_item( "palo_alto_pan_os/model" );
if(version_is_less( version: version, test_version: "6.1.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1.17" );
	if(model){
		report += "\nModel:             " + model;
	}
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.0" )){
	if(version_is_less( version: version, test_version: "7.0.15" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.0.15" );
		if(model){
			report += "\nModel:             " + model;
		}
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^7\\.1" )){
	if(version_is_less( version: version, test_version: "7.1.10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "7.1.10" );
		if(model){
			report += "\nModel:             " + model;
		}
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^8\\.0" )){
	if(version_is_less( version: version, test_version: "8.0.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.0.1" );
		if(model){
			report += "\nModel:             " + model;
		}
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

