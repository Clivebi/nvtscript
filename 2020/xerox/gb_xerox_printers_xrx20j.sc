if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144163" );
	script_version( "2021-09-06T12:18:51+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 12:18:51 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-06-24 09:37:40 +0000 (Wed, 24 Jun 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-22 00:15:00 +0000 (Wed, 22 Jul 2020)" );
	script_cve_id( "CVE-2020-11896", "CVE-2020-11897", "CVE-2020-11898", "CVE-2020-11899", "CVE-2020-11900", "CVE-2020-11901", "CVE-2020-11902", "CVE-2020-11903", "CVE-2020-11904", "CVE-2020-11905", "CVE-2020-11906", "CVE-2020-11907", "CVE-2020-11908", "CVE-2020-11909", "CVE-2020-11910", "CVE-2020-11911", "CVE-2020-11912", "CVE-2020-11913", "CVE-2020-11914" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Xerox Printers Multiple Vulnerabilities - Ripple20 (XRX20J)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_xerox_printer_consolidation.sc" );
	script_mandatory_keys( "xerox/printer/detected" );
	script_tag( name: "summary", value: "Xerox printers are prone to multiple vulnerabilities in the Treck IP Stack (Ripple20)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable firmware version is present on the target host." );
	script_tag( name: "affected", value: "Xerox B205, B210 and B215 devices." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://security.business.xerox.com/wp-content/uploads/2020/06/cert_Security_Mini_Bulletin_XRX20J_for_B2XX.pdf" );
	script_xref( name: "URL", value: "https://kb.cert.org/vuls/id/257161" );
	script_xref( name: "URL", value: "https://treck.com/vulnerability-response-information/" );
	script_xref( name: "URL", value: "https://www.jsof-tech.com/ripple20/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:xerox:b205_firmware",
	 "cpe:/o:xerox:b210_firmware",
	 "cpe:/o:xerox:b215_firmware" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
if(!version = get_app_version( cpe: cpe, nofork: TRUE )){
	exit( 0 );
}
if(cpe == "cpe:/o:xerox:b205_firmware" || cpe == "cpe:/o:xerox:b210_firmware"){
	if(version_is_less( version: version, test_version: "85.000.59.000" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "85.000.59.000" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(cpe == "cpe:/o:xerox:b215_firmware"){
	if(version_is_less( version: version, test_version: "88.000.63.000" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "88.000.63.000" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

