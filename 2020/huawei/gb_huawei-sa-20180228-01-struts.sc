if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107824" );
	script_version( "2021-08-03T11:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-03 11:00:50 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 21:56:00 +0000 (Thu, 25 Feb 2021)" );
	script_cve_id( "CVE-2017-7525" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Remote Code Execution Vulnerability in Jackson JSON library of Apache Struts2 (huawei-sa-20180228-01-struts)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Apache Struts2 released a remote code execution vulnerability in S2-055 on the official website." );
	script_tag( name: "insight", value: "Apache Struts2 released a remote code execution vulnerability in S2-055 on the official website. An attacker is possible to perform a Remote Code Execution(RCE) attack with a malicious JSON packet. (Vulnerability ID: HWPSIRT-2017-12002)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-7525.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker is possible to perform a RCE (Remote Code Execution) attack with a malicious JSON packet." );
	script_tag( name: "affected", value: "eSDK versions 3.1.0 3.1.0.SPC100" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180228-01-struts-en" );
	exit( 0 );
}

