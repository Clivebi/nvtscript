if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2908.1" );
	script_cve_id( "CVE-2016-10277", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-11176", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-12192", "CVE-2017-12762", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-15649", "CVE-2017-6346", "CVE-2017-7482", "CVE-2017-7487", "CVE-2017-7518", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8831", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-06 01:29:00 +0000 (Fri, 06 Apr 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2908-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2908-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172908-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2908-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP1 LTS kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-15649: net/packet/af_packet.c in the Linux kernel allowed local
 users to gain privileges via crafted system calls that trigger
 mishandling of packet_fanout data structures, because of a race
 condition (involving fanout_add and packet_do_bind) that leads to a
 use-after-free, a different vulnerability than CVE-2017-6346
 (bnc#1064388).
- CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2) allowed
 reinstallation of the Group Temporal Key (GTK) during the group key
 handshake, allowing an attacker within radio range to replay frames from
 access points to clients (bnc#1063667).
- CVE-2017-15274: security/keys/keyctl.c in the Linux kernel did not
 consider the case of a NULL payload in conjunction with a nonzero length
 value, which allowed local users to cause a denial of service (NULL
 pointer dereference and OOPS) via a crafted add_key or keyctl system
 call, a different vulnerability than CVE-2017-12192 (bnc#1045327).
- CVE-2017-15265: Use-after-free vulnerability in the Linux kernel allowed
 local users to have unspecified impact via vectors related to
 /dev/snd/seq (bnc#1062520).
- CVE-2017-1000365: The Linux Kernel imposes a size restriction on the
 arguments and environmental strings passed through
 RLIMIT_STACK/RLIM_INFINITY (1/4 of the size), but did not take the
 argument and environment pointers into account, which allowed attackers
 to bypass this limitation. (bnc#1039354).
- CVE-2017-12153: A security flaw was discovered in the
 nl80211_set_rekey_data() function in net/wireless/nl80211.c in the Linux
 kernel This function did not check whether the required attributes are
 present in a Netlink request. This request can be issued by a user with
 the CAP_NET_ADMIN capability and may result in a NULL pointer
 dereference and system crash (bnc#1058410).
- CVE-2017-12154: The prepare_vmcs02 function in arch/x86/kvm/vmx.c in the
 Linux kernel did not ensure that the 'CR8-load exiting' and 'CR8-store
 exiting' L0 vmcs02 controls exist in cases where L1 omits the 'use TPR
 shadow' vmcs12 control, which allowed KVM L2 guest OS users to obtain
 read and write access to the hardware CR8 register (bnc#1058507).
- CVE-2017-14106: The tcp_disconnect function in net/ipv4/tcp.c in the
 Linux kernel allowed local users to cause a denial of service
 (__tcp_select_window divide-by-zero error and system crash) by
 triggering a disconnect within a certain tcp_recvmsg code path
 (bnc#1056982).
- CVE-2017-14140: The move_pages system call in mm/migrate.c in the Linux
 kernel doesn't check the effective uid of the target process, enabling a
 local attacker to learn the memory layout of a setuid executable despite
 ASLR (bnc#1057179).
- CVE-2017-14051: An integer overflow in the
 qla2x00_sysfs_write_optrom_ctl function in
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE OpenStack Cloud 6." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.74~60.64.63.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.74~60.64.63.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.74~60.64.63.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.74~60.64.63.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.74~60.64.63.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.74~60.64.63.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.74~60.64.63.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_63-default", rpm: "kgraft-patch-3_12_74-60_64_63-default~1~2.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_63-xen", rpm: "kgraft-patch-3_12_74-60_64_63-xen~1~2.1", rls: "SLES12.0SP1" ) )){
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

