if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108794" );
	script_version( "2021-08-03T11:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-03 11:00:50 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 18:15:00 +0000 (Thu, 03 Jun 2021)" );
	script_cve_id( "CVE-2019-0708" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: Remote Code Execution Vulnerability in Some Microsoft Windows Systems (huawei-sa-20190529-01-windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Microsoft released a security advisory to disclose a remote code execution vulnerability in Remote Desktop Services." );
	script_tag( name: "insight", value: "Microsoft released a security advisory to disclose a remote code execution vulnerability in Remote Desktop Services. An unauthenticated attacker connects to the target system using RDP and sends specially crafted requests to exploit the vulnerability. Successful exploit may cause arbitrary code execution on the target system. (Vulnerability ID: HWPSIRT-2019-05133)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-0708.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "An attacker who successfully exploited this vulnerability could execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "OceanStor HVS85T versions V100R001C00

OceanStor HVS88T versions V100R001C00

SMC2.0 versions V500R002C00 V600R006C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190529-01-windows-en" );
	exit( 0 );
}

