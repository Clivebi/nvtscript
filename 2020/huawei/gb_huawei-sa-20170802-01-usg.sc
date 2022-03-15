CPE = "cpe:/o:huawei:usg6300_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143951" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-20 08:29:59 +0000 (Wed, 20 May 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-12 18:08:00 +0000 (Tue, 12 Dec 2017)" );
	script_cve_id( "CVE-2017-8174" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Weak Algorithm Vulnerability in Huawei USG product (huawei-sa-20170802-01-usg)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a weak algorithm vulnerability in Huawei USG(USG6300/USG6600) products." );
	script_tag( name: "insight", value: "There is a weak algorithm vulnerability in Huawei USG(USG6300/USG6600) products. Attackers may exploit the weak algorithm vulnerability to crack the cipher text and cause confidential information leaks on the transmission links. (Vulnerability ID: HWPSIRT-2017-02028)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-8174.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Attackers may exploit this vulnerability to crack the cipher text and cause confidential information leaks on the transmission links." );
	script_tag( name: "affected", value: "IPS Module versions V100R001C30SPC600

NGFW Module versions V100R001C30SPC600

Secospace USG6300 versions V100R001C30SPC300

Secospace USG6600 versions V100R001C30SPC500 V100R001C30SPC600 V100R001C30SPC700 V100R001C30SPC800" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170802-01-usg-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
version = toupper( version );
if(IsMatchRegexp( version, "^V100R001C30SPC300" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "V100R001C30SPC900" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

