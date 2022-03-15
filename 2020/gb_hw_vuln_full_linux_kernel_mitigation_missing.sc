if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108767" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754", "CVE-2019-1125", "CVE-2018-3639", "CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-12126", "CVE-2018-12130", "CVE-2018-12127", "CVE-2019-11091", "CVE-2019-11135", "CVE-2018-12207", "CVE-2020-0543" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Missing Linux Kernel mitigations for hardware vulnerabilities (sysfs interface not available)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hw_vuln_linux_kernel_mitigation_detect.sc" );
	script_mandatory_keys( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available" );
	script_xref( name: "URL", value: "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html" );
	script_tag( name: "summary", value: "The remote host is missing all known mitigation(s) on Linux Kernel
  side for the referenced hardware vulnerabilities.

  Note: The sysfs interface to read the migitation status from the Linux Kernel is not available. Based on this it is
  assumed that no Linux Kernel mitigations are available and that the host is affected by all vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks previous gathered information on the mitigation status reported
  by the Linux Kernel." );
	script_tag( name: "solution", value: "Enable the mitigation(s) in the Linux Kernel or update to a more
  recent Linux Kernel." );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available" )){
	exit( 99 );
}
report = get_kb_item( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available/report" );
if(report){
	register_host_detail( name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.108765" );
	register_host_detail( name: "detected_at", value: "general/tcp" );
	report += " If this is wrong please make the sysfs interface available for the scanning user.";
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

