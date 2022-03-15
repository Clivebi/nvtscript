if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108784" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-17164" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Memory Leak Vulnerability in Some Huawei AntiDDOS Products (huawei-sa-20171213-01-antidos)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There has a memory leak vulnerability in some Huawei AntiDDOS Products." );
	script_tag( name: "insight", value: "There has a memory leak vulnerability in some Huawei AntiDDOS Products. When open some function, the memory leaking happened, which would cause the device to reset finally. (Vulnerability ID: HWPSIRT-2017-06145)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17164.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "A successful exploit could cause the device to reset." );
	script_tag( name: "affected", value: "Secospace AntiDDoS8000 versions V500R001C20SPC500" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-01-antidos-en" );
	exit( 0 );
}

