if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2610.1" );
	script_cve_id( "CVE-2020-10135", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14386", "CVE-2020-16166", "CVE-2020-1749", "CVE-2020-24394" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2610-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2610-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202610-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2610-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-1749: Use ip6_dst_lookup_flow instead of ip6_dst_lookup
 (bsc#1165629).

CVE-2020-14314: Fixed a potential negative array index in do_split()
 (bsc#1173798).

CVE-2020-14356: Fixed a null pointer dereference in cgroupv2 subsystem
 which could have led to privilege escalation (bsc#1175213).

CVE-2020-14331: Fixed a missing check in vgacon scrollback handling
 (bsc#1174205).

CVE-2020-16166: Fixed a potential issue which could have allowed remote
 attackers to make observations that help to obtain sensitive information
 about the internal state of the network RNG (bsc#1174757).

CVE-2020-24394: Fixed an issue which could set incorrect permissions on
 new filesystem objects when the filesystem lacks ACL support
 (bsc#1175518).

CVE-2020-10135: Legacy pairing and secure-connections pairing
 authentication Bluetooth might have allowed an unauthenticated user to
 complete authentication without pairing credentials via adjacent access
 (bsc#1171988).

CVE-2020-14386: Fixed a potential local privilege escalation via memory
 corruption (bsc#1176069).

The following non-security bugs were fixed:

cifs: add support for fallocate mode 0 for non-sparse files
 (bsc#1175122).

cifs: allow unlock flock and OFD lock across fork (bsc#1175122).

cifs_atomic_open(): fix double-put on late allocation failure
 (bsc#1175122).

cifs: Avoid doing network I/O while holding cache lock (bsc#1175122).

cifs: call wake_up(&server->response_q) inside of cifs_reconnect()
 (bsc#1175122).

cifs: Clean up DFS referral cache (bsc#1175122).

cifs: document and cleanup dfs mount (bsc#1172428 bsc#1175122).

cifs: do not ignore the SYNC flags in getattr (bsc#1175122).

cifs: do not leak -EAGAIN for stat() during reconnect (bsc#1175122).

cifs: do not share tcons with DFS (bsc#1175122).

cifs: ensure correct super block for DFS reconnect (bsc#1175122).

cifs: fail i/o on soft mounts if sessionsetup errors out (bsc#1175122).

cifs: fiemap: do not return EINVAL if get nothing (bsc#1175122).

cifs: Fix an error pointer dereference in cifs_mount() (bsc#1172428
 bsc#1175122).

cifs: fix double free error on share and prefix (bsc#1172428
 bsc#1175122).

cifs: fix leaked reference on requeued write (bsc#1175122).

cifs: fix NULL dereference in match_prepath (bsc#1175122).

cifs: Fix null pointer check in cifs_read (bsc#1175122).

cifs: Fix potential deadlock when updating vol in cifs_reconnect()
 (bsc#1175122).

cifs: fix potential mismatch of UNC paths (bsc#1175122).

cifs: fix rename() by ensuring source handle opened with DELETE bit
 (bsc#1175122).

cifs: Fix return value in __update_cache_entry (bsc#1175122).

cifs: fix soft mounts hanging in the reconnect code (bsc#1175122).

cifs: Fix task struct use-after-free on reconnect (bsc#1175122).

cifs: fix uninitialised lease_key ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-base", rpm: "kernel-vanilla-base~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-base-debuginfo", rpm: "kernel-vanilla-base-debuginfo~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debuginfo", rpm: "kernel-vanilla-debuginfo~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debugsource", rpm: "kernel-vanilla-debugsource~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-zfcpdump-debuginfo", rpm: "kernel-zfcpdump-debuginfo~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-zfcpdump-debugsource", rpm: "kernel-zfcpdump-debugsource~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default", rpm: "reiserfs-kmp-default~4.12.14~150.58.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default-debuginfo", rpm: "reiserfs-kmp-default-debuginfo~4.12.14~150.58.1", rls: "SLES15.0" ) )){
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

