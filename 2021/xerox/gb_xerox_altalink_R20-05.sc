if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145610" );
	script_version( "2021-09-06T11:58:24+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:58:24 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-03-24 03:14:50 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-11 13:46:00 +0000 (Thu, 11 Mar 2021)" );
	script_cve_id( "CVE-2019-18628", "CVE-2019-18630" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Xerox AltaLink Printers < 103.008.010.14010 Multiple Vulnerabilities (R20-05)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_xerox_printer_consolidation.sc" );
	script_mandatory_keys( "xerox/printer/detected" );
	script_tag( name: "summary", value: "Xerox AltaLink Printers are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable firmware version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2019-18628: Cryptographic information disclosure

  - CVE-2019-18630: Cryptographic information disclosure" );
	script_tag( name: "affected", value: "Xerox AltaLink B80xx, C8030, C8035, C8045, C8055 and C8070 prior to
  firmware version 103.008.010.14010." );
	script_tag( name: "solution", value: "Update to version 103.008.010.14010 or later." );
	script_xref( name: "URL", value: "https://securitydocs.business.xerox.com/wp-content/uploads/2021/03/cert_Security_Mini_Bulletin_XRX20I_for_ALB80xx-C80xx_v1.2.pdf" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:xerox:altalink_b8045_firmware",
	 "cpe:/o:xerox:altalink_b8055_firmware",
	 "cpe:/o:xerox:altalink_b8065_firmware",
	 "cpe:/o:xerox:altalink_b8075_firmware",
	 "cpe:/o:xerox:altalink_b8090_firmware",
	 "cpe:/o:xerox:altalink_c8030_firmware",
	 "cpe:/o:xerox:altalink_c8035_firmware",
	 "cpe:/o:xerox:altalink_c8045_firmware",
	 "cpe:/o:xerox:altalink_c8055_firmware",
	 "cpe:/o:xerox:altalink_c8070_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
version = infos["version"];
if(version_is_less( version: version, test_version: "103.008.010.14010" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "103.008.010.14010" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

