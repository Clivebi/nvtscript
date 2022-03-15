if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1773.1" );
	script_cve_id( "CVE-2017-9217" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-06 19:18:00 +0000 (Tue, 06 Jun 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1773-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1773-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171773-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2017:1773-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for systemd fixes the following issues:
Security issue fixed:
- CVE-2017-9217: resolved: Fix null pointer p->question dereferencing that
 could lead to resolved aborting (bsc#1040614)
The update also fixed several non-security bugs:
- core/mount: Use the '-c' flag to not canonicalize paths when calling
 /bin/umount
- automount: Handle expire_tokens when the mount unit changes its state
 (bsc#1040942)
- automount: Rework propagation between automount and mount units
- build: Make sure tmpfiles.d/systemd-remote.conf get installed when
 necessary
- build: Fix systemd-journal-upload installation
- basic: Detect XEN Dom0 as no virtualization (bsc#1036873)
- virt: Make sure some errors are not ignored
- fstab-generator: Do not skip Before= ordering for noauto mountpoints
- fstab-gen: Do not convert device timeout into seconds when initializing
 JobTimeoutSec
- core/device: Use JobRunningTimeoutSec= for device units (bsc#1004995)
- fstab-generator: Apply the _netdev option also to device units
 (bsc#1004995)
- job: Add JobRunningTimeoutSec for JOB_RUNNING state (bsc#1004995)
- job: Ensure JobRunningTimeoutSec= survives serialization (bsc#1004995)
- rules: Export NVMe WWID udev attribute (bsc#1038865)
- rules: Introduce disk/by-id (model_serial) symbolic links for NVMe drives
- rules: Add rules for NVMe devices
- sysusers: Make group shadow support configurable (bsc#1029516)
- core: When deserializing a unit, fully restore its cgroup state
 (bsc#1029102)
- core: Introduce cg_mask_from_string()/cg_mask_to_string()
- core:execute: Fix handling failures of calling fork() in exec_spawn()
 (bsc#1040258)
- Fix systemd-sysv-convert when a package starts shipping service units
 (bsc#982303) The database might be missing when upgrading a package
 which was shipping no sysv init scripts nor unit files (at the time
 --save was called) but the new version start shipping unit files.
- Disable group shadow support (bsc#1029516)
- Only check signature job error if signature job exists (bsc#1043758)" );
	script_tag( name: "affected", value: "'systemd' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo-32bit", rpm: "libsystemd0-debuginfo-32bit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo-32bit", rpm: "libudev1-debuginfo-32bit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-bash-completion", rpm: "systemd-bash-completion~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo-32bit", rpm: "systemd-debuginfo-32bit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~228~149.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~228~149.3", rls: "SLES12.0SP2" ) )){
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

