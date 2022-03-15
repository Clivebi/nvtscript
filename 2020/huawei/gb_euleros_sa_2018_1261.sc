if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1261" );
	script_cve_id( "CVE-2017-18255", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-8781" );
	script_tag( name: "creation_date", value: "2020-01-23 11:19:22 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-19 11:29:00 +0000 (Sat, 19 Jan 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2018-1261)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1261" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1261" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2018-1261 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was found in the Linux kernel's kernel/events/core.c:perf_cpu_time_max_percent_handler() function. Local privileged users could exploit this flaw to cause a denial of service due to integer overflow or possibly have unspecified other impact.(CVE-2017-18255)

The code in the drivers/scsi/libsas/sas_scsi_host.c file in the Linux kernel allow a physically proximate attacker to cause a memory leak in the ATA command queue and, thus, denial of service by triggering certain failure conditions.(CVE-2018-10021)

The kernel_wait4 function in kernel/exit.c in the Linux kernel, when an unspecified architecture and compiler is used, might allow local users to cause a denial of service by triggering an attempted use of the -INT_MIN value.(CVE-2018-10087)

A an integer overflow vulnerability was discovered in the Linux kernel, from version 3.4 through 4.15, in the drivers/gpu/drm/udl/udl_fb.c:udl_fb_mmap() function. An attacker with access to the udldrmfb driver could exploit this to obtain full read and write permissions on kernel physical pages, resulting in a code execution in kernel space.(CVE-2018-8781)" );
	script_tag( name: "affected", value: "'kernel' package(s) on Huawei EulerOS Virtualization 2.5.1." );
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
if(release == "EULEROSVIRT-2.5.1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~514.44.5.10_31", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~514.44.5.10_31", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~514.44.5.10_31", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~514.44.5.10_31", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~514.44.5.10_31", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~514.44.5.10_31", rls: "EULEROSVIRT-2.5.1" ) )){
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
