if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1515" );
	script_cve_id( "CVE-2014-8171", "CVE-2017-12762", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-9725", "CVE-2018-3620", "CVE-2018-3639", "CVE-2018-3646", "CVE-2018-9516", "CVE-2018-9568" );
	script_tag( name: "creation_date", value: "2020-01-23 12:01:21 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-06 01:29:00 +0000 (Fri, 06 Apr 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1515)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1515" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1515" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1515 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found where the kernel truncated the value used to indicate the size of a buffer which it would later become zero using an untruncated value. This can corrupt memory outside of the original allocation.(CVE-2017-9725)

An industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimization). There are three primary variants of the issue which differ in the way the speculative execution can be exploited. Variant CVE-2017-5753 triggers the speculative execution by performing a bounds-check bypass. It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory accesses may cause allocation into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to cross the syscall boundary and read privileged memory by conducting targeted cache side-channel attacks.(CVE-2017-5753)

A buffer overflow was found in the Linux kernel's isdn_net_newslave() function in the /drivers/isdn/i4l/isdn_net.c file. An overflow happens when the user-controlled buffer is copied into a local buffer of constant size using strcpy() without a length check.(CVE-2017-12762)

Modern operating systems implement virtualization of physical memory to efficiently use available system resources and provide inter-domain protection through access control and isolation. The L1TF issue was found in the way the x86 microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimization) in combination with handling of page-faults caused by terminated virtual to physical address resolving process. As a result, an unprivileged attacker could use this flaw to read privileged memory of the kernel or other processes and/or cross guest/host boundaries to read host memory by conducting targeted cache side-channel attacks.(CVE-2018-3646)

An industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimization). There are three primary variants of the issue which differ in the way the speculative execution can be exploited. Variant CVE-2017-5715 triggers the speculative execution by utilizing branch target injection. It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory accesses may cause allocation into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to cross the syscall and guest/host boundaries and read privileged memory by conducting targeted cache side-channel attacks.(CVE-2017-5715)

Modern ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~862.14.1.6_42", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

