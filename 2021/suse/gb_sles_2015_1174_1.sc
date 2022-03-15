if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1174.1" );
	script_cve_id( "CVE-2014-8086", "CVE-2014-8159", "CVE-2014-9419", "CVE-2014-9529", "CVE-2014-9683", "CVE-2015-0777", "CVE-2015-1421", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3339", "CVE-2015-3636" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 18:16:00 +0000 (Fri, 14 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1174-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1174-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151174-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:1174-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to fix various bugs and security issues.
The following vulnerabilities have been fixed:
CVE-2015-3636: A missing sk_nulls_node_init() in ping_unhash() inside the ipv4 stack can cause crashes if a disconnect is followed by another connect() attempt. (bnc#929525)
CVE-2015-3339: Race condition in the prepare_binprm function in fs/exec.c in the Linux kernel before 3.19.6 allows local users to gain privileges by executing a setuid program at a time instant when a chown to root is in progress, and the ownership is changed but the setuid bit is not yet stripped. (bnc#928130)
CVE-2015-3331: The __driver_rfc4106_decrypt function in arch/x86/crypto/aesni-intel_glue.c in the Linux kernel before 3.19.3 does not properly determine the memory locations used for encrypted data, which allows context-dependent attackers to cause a denial of service (buffer overflow and system crash) or possibly execute arbitrary code by triggering a crypto API call, as demonstrated by use of a libkcapi test program with an AF_ALG(aead) socket. (bnc#927257)
CVE-2015-2922: The ndisc_router_discovery function in net/ipv6/ndisc.c in the Neighbor Discovery (ND) protocol implementation in the IPv6 stack in the Linux kernel before 3.19.6 allows remote attackers to reconfigure a hop-limit setting via a small hop_limit value in a Router Advertisement (RA) message. (bnc#922583)
CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux kernel before 3.19.2 does not prevent the TS_COMPAT flag from reaching a user-mode task, which might allow local users to bypass the seccomp or audit protection mechanism via a crafted application that uses the (1) fork or (2) close system call, as demonstrated by an attack against seccomp before 3.16. (bnc#926240)
CVE-2015-2150: XSA-120: Xen 3.3.x through 4.5.x and the Linux kernel through 3.19.1 do not properly restrict access to PCI command registers, which might allow local guest users to cause a denial of service (non-maskable interrupt and host crash) by disabling the (1) memory or (2) I/O decoding for a PCI Express device and then accessing the device, which triggers an Unsupported Request (UR) response. (bnc#919463)
CVE-2015-2042: net/rds/sysctl.c in the Linux kernel before 3.19 uses an incorrect data type in a sysctl table, which allows local users to obtain potentially sensitive information from kernel memory or possibly have unspecified other impact by accessing a sysctl entry. (bnc#919018)
CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux kernel before 3.19 uses an incorrect data type in a sysctl table, which allows local users to obtain potentially sensitive information from kernel memory or possibly have unspecified other impact by accessing a sysctl entry. (bnc#919007)
CVE-2015-1421: Use-after-free vulnerability in the sctp_assoc_update function in net/sctp/associola.c in the Linux kernel before 3.18.8 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SLE 11, SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise High Availability Extension 11 SP3, SUSE Linux Enterprise Server 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp", rpm: "kernel-bigsmp~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp-base", rpm: "kernel-bigsmp-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp-devel", rpm: "kernel-bigsmp-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-base", rpm: "kernel-ppc64-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-devel", rpm: "kernel-ppc64-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~0.47.55.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.2.5_08_3.0.101_0.47.55~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-pae", rpm: "xen-kmp-pae~4.2.5_08_3.0.101_0.47.55~0.7.1", rls: "SLES11.0SP3" ) )){
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

