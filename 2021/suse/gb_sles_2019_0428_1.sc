if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0428.1" );
	script_cve_id( "CVE-2019-6454" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0428-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0428-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190428-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2019:0428-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for systemd fixes the following issues:

Security vulnerability fixed:
CVE-2019-6454: Fixed a crash of PID1 by sending specially crafted D-BUS
 message on the system bus by an unprivileged user (bsc#1125352)

Other bug fixes and changes:
journal-remote: set a limit on the number of fields in a message

journal-remote: verify entry length from header

journald: set a limit on the number of fields (1k)

journald: do not store the iovec entry for process commandline on stack

core: include Found state in device dumps

device: fix serialization and deserialization of DeviceFound

fix path in btrfs rule (#6844)

assemble multidevice btrfs volumes without external tools (#6607)
 (bsc#1117025)

Update systemd-system.conf.xml (bsc#1122000)

units: inform user that the default target is started after exiting from
 rescue or emergency mode

manager: don't skip sigchld handler for main and control pid for
 services (#3738)

core: Add helper functions unit_{main, control}_pid

manager: Fixing a debug printf formatting mistake (#3640)

manager: Only invoke a single sigchld per unit within a cleanup cycle
 (bsc#1117382)

core: update invoke_sigchld_event() to handle NULL ->sigchld_event()

sd-event: expose the event loop iteration counter via
 sd_event_get_iteration() (#3631)

unit: rework a bit how we keep the service fdstore from being destroyed
 during service restart (bsc#1122344)

core: when restarting services, don't close fds

cryptsetup: Add dependency on loopback setup to generated units

journal-gateway: use localStorage['cursor'] only when it has valid value

journal-gateway: explicitly declare local variables

analyze: actually select longest activated-time of services

sd-bus: fix implicit downcast of bitfield reported by LGTM

core: free lines after reading them (bsc#1123892)

pam_systemd: reword message about not creating a session (bsc#1111498)

pam_systemd: suppress LOG_DEBUG log messages if debugging is off
 (bsc#1111498)

main: improve RLIMIT_NOFILE handling (#5795) (bsc#1120658)

sd-bus: if we receive an invalid dbus message, ignore and proceeed

automount: don't pass non-blocking pipe to kernel.

units: make sure initrd-cleanup.service terminates before switching to
 rootfs (bsc#1123333)

units: add Wants=initrd-cleanup.service to initrd-switch-root.target
 (#4345) (bsc#1123333)" );
	script_tag( name: "affected", value: "'systemd' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo-32bit", rpm: "libsystemd0-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo-32bit", rpm: "libudev1-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-bash-completion", rpm: "systemd-bash-completion~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo-32bit", rpm: "systemd-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~228~150.63.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~228~150.63.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo-32bit", rpm: "libsystemd0-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo-32bit", rpm: "libudev1-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-bash-completion", rpm: "systemd-bash-completion~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo-32bit", rpm: "systemd-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~228~150.63.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~228~150.63.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo-32bit", rpm: "libsystemd0-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo-32bit", rpm: "libudev1-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-bash-completion", rpm: "systemd-bash-completion~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo-32bit", rpm: "systemd-debuginfo-32bit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~228~150.63.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~228~150.63.1", rls: "SLES12.0SP4" ) )){
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

