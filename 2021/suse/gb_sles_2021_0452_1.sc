if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0452.1" );
	script_cve_id( "CVE-2018-10902", "CVE-2019-20934", "CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-11668", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25211", "CVE-2020-25285", "CVE-2020-25669", "CVE-2020-27068", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-27835", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2020-4788", "CVE-2021-3347" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0452-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0452-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210452-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0452-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3347: A use-after-free was discovered in the PI futexes during
 fault handling, allowing local users to execute code in the kernel
 (bnc#1181349).

CVE-2020-25211: Fixed a buffer overflow in
 ctnetlink_parse_tuple_filter() which could be triggered by a local
 attackers by injecting conntrack netlink configuration (bnc#1176395).

CVE-2020-27835: A use-after-free in the infiniband hfi1 driver was
 found, specifically in the way user calls Ioctl after open dev file and
 fork. A local user could use this flaw to crash the system (bnc#1179878).

CVE-2020-29569: Fixed a potential privilege escalation and information
 leaks related to the PV block backend, as used by Xen (bnc#1179509).

CVE-2020-29568: Fixed a denial of service issue, related to processing
 watch events (bnc#1179508).

CVE-2020-0444: Fixed a bad kfree due to a logic error in
 audit_data_to_entry (bnc#1180027).

CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c
 that could have led to local privilege escalation (bnc#1180029).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
 do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).

CVE-2020-4788: Fixed an issue with IBM Power9 processors could have
 allowed a local user to obtain sensitive information from the data in
 the L1 cache under extenuating circumstances (bsc#1177666).

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
 which could have allowed local users to gain privileges or cause a
 denial of service (bsc#1179141).

CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds
 check in the nl80211_policy policy of nl80211.c (bnc#1180086).

CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction
 Services (RTAS) interface, affecting guests running on top of PowerVM or
 KVM hypervisors (bnc#1179107).

CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation
 (bnc#1179601).

CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls
 (bsc#1179960).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that
 may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed
 a use-after-free attack against TIOCSPGRP (bsc#1179745).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
 have been used by local attackers to read privileged information or
 potentially crash the kernel (bsc#1178589).

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
 have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
 (bsc#1178182).

CVE-2020-15437: Fixed a null pointer dereference which could have
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-kgraft", rpm: "kernel-default-kgraft~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.180~94.138.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_138-default", rpm: "kgraft-patch-4_4_180-94_138-default~1~4.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_138-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_138-default-debuginfo~1~4.3.1", rls: "SLES12.0SP3" ) )){
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

