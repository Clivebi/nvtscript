CPE = "cpe:/o:paloaltonetworks:pan-os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105810" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_name( "Palo Alto PAN-OS OpenSSH vulnerabilities (PAN-SA-2016-0011)" );
	script_xref( name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/44" );
	script_tag( name: "summary", value: "OpenSSH contains two vulnerabilities (CVE-2016-0777 and CVE-2016-0778) affecting the SSH client roaming feature when connecting to a malicious server. Exploitation of this issue can leak portions of memory from the SSH client process." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to PAN-OS 7.1.3 or later" );
	script_tag( name: "impact", value: "The Palo Alto Networks firewall outbound SSH client offers only the user/password authentication scheme and, therefore, does not expose a potential SSH private key." );
	script_tag( name: "affected", value: "PAN-OS 5.0.X, PAN-OS 5.1.X, PAN-OS 6.0.X, PAN-OS 6.1.X, PAN-OS 7.0.X, PAN-OS 7.1.2 and earlier" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-07-14 10:36:09 +0200 (Thu, 14 Jul 2016)" );
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
if(version_is_less( version: version, test_version: "7.1.3" )){
	fix = "7.1.3";
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

