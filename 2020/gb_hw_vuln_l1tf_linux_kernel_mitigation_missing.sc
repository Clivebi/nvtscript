if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108839" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_cve_id( "CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-12 14:03:21 +0000 (Wed, 12 Aug 2020)" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Missing Linux Kernel mitigations for 'L1TF - L1 Terminal Fault' hardware vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hw_vuln_linux_kernel_mitigation_detect.sc" );
	script_mandatory_keys( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable" );
	script_xref( name: "URL", value: "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html" );
	script_tag( name: "summary", value: "The remote host is missing one or more known mitigation(s) on Linux Kernel
  side for the referenced 'L1TF - L1 Terminal Fault' hardware vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks previous gathered information on the mitigation status reported
  by the Linux Kernel." );
	script_tag( name: "solution", value: "Enable the mitigation(s) in the Linux Kernel or update to a more
  recent Linux Kernel." );
	script_tag( name: "qod", value: "80" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable" )){
	exit( 99 );
}
covered_vuln = "l1tf";
mitigation_status = get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + covered_vuln );
if(!mitigation_status){
	exit( 99 );
}
report = "The Linux Kernel on the remote host is missing the mitigation for the \"" + covered_vuln + "\" hardware vulnerabilities as reported by the sysfs interface:\n\n";
path = "/sys/devices/system/cpu/vulnerabilities/" + covered_vuln;
info[path] = mitigation_status;
register_host_detail( name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.108765" );
register_host_detail( name: "detected_at", value: "general/tcp" );
report += text_format_table( array: info, sep: " | ", columnheader: make_list( "sysfs file checked",
	 "Kernel status (SSH response)" ) );
report += "\n\nNotes on the \"Kernel status / SSH response\" column:";
report += "\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the kernel doesn\'t know this vulnerability yet and is not providing any mitigation which means the target system is vulnerable.";
report += "\n- Strings including \"Mitigation:\", \"Not affected\" or \"Vulnerable\" are reported directly by the Linux Kernel.";
report += "\n- All other strings are responses to various SSH commands.";
security_message( port: 0, data: report );
exit( 0 );

