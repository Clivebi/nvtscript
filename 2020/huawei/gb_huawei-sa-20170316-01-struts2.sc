if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108771" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_cve_id( "CVE-2017-5638" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Apache Struts2 Remote Code Execution Vulnerability in Huawei Products (huawei-sa-20170316-01-struts2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Apache Struts2 released a remote code execution vulnerability in S2-045 on the official website." );
	script_tag( name: "insight", value: "Apache Struts2 released a remote code execution vulnerability in S2-045 on the official website. An attacker is possible to perform a RCE (Remote Code Execution) attack with a malicious Content-Type value. (Vulnerability ID: HWPSIRT-2017-03094)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-5638.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker is possible to perform a RCE (Remote Code Execution) attack with a malicious Content-Type value." );
	script_tag( name: "affected", value: "AAA versions V300R003C30 V500R005C00 V500R005C10 V500R005C11 V500R005C12

AnyOffice versions 2.5.0302.0201T 2.5.0501.0290

iManager NetEco 6000 versions V600R007C91" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170316-01-struts2-en" );
	exit( 0 );
}

