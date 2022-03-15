if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852324" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-6454" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-02-28 04:08:24 +0100 (Thu, 28 Feb 2019)" );
	script_name( "openSUSE: Security Advisory for systemd (openSUSE-SU-2019:0255-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:0255-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00070.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2019:0255-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for systemd fixes the following issues:

  - CVE-2019-6454: Overlong DBUS messages could be used to crash systemd
  (bsc#1125352)

  - units: make sure initrd-cleanup.service terminates before switching to
  rootfs (bsc#1123333)

  - logind: fix bad error propagation

  - login: log session state 'closing' (as well as New/Removed)

  - logind: fix borked r check

  - login: don't remove all devices from PID1 when only one was removed

  - login: we only allow opening character devices

  - login: correct comment in session_device_free()

  - login: remember that fds received from PID1 need to be removed eventually

  - login: fix FDNAME in call to sd_pid_notify_with_fds()

  - logind: fd 0 is a valid fd

  - logind: rework sd_eviocrevoke()

  - logind: check file is device node before using .st_rdev

  - logind: use the new FDSTOREREMOVE=1 sd_notify() message (bsc#1124153)

  - core: add a new sd_notify() message for removing fds from the FD store
  again

  - logind: make sure we don't trip up on half-initialized session devices
  (bsc#1123727)

  - fd-util: accept that kcmp might fail with EPERM/EACCES

  - core: Fix use after free case in load_from_path() (bsc#1121563)

  - core: include Found state in device dumps

  - device: fix serialization and deserialization of DeviceFound

  - fix path in btrfs rule (#6844)

  - assemble multidevice btrfs volumes without external tools (#6607)
  (bsc#1117025)

  - Update systemd-system.conf.xml (bsc#1122000)

  - units: inform user that the default target is started after exiting from
  rescue or emergency mode

  - core: free lines after reading them (bsc#1123892)

  - sd-bus: if we receive an invalid dbus message, ignore and proceed

  - automount: don't pass non-blocking pipe to kernel.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-255=1" );
	script_tag( name: "affected", value: "systemd on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-mini", rpm: "libsystemd0-mini~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-mini-debuginfo", rpm: "libsystemd0-mini-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-devel", rpm: "libudev-devel~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-mini-devel", rpm: "libudev-mini-devel~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-mini1", rpm: "libudev-mini1~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-mini1-debuginfo", rpm: "libudev-mini1-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname", rpm: "nss-myhostname~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-debuginfo", rpm: "nss-myhostname-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines", rpm: "nss-mymachines~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-debuginfo", rpm: "nss-mymachines-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-systemd", rpm: "nss-systemd~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-systemd-debuginfo", rpm: "nss-systemd-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-container", rpm: "systemd-container~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-container-debuginfo", rpm: "systemd-container-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-coredump", rpm: "systemd-coredump~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-coredump-debuginfo", rpm: "systemd-coredump-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-devel", rpm: "systemd-devel~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-logger", rpm: "systemd-logger~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini", rpm: "systemd-mini~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-container-mini", rpm: "systemd-mini-container-mini~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-container-mini-debuginfo", rpm: "systemd-mini-container-mini-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-coredump-mini", rpm: "systemd-mini-coredump-mini~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-coredump-mini-debuginfo", rpm: "systemd-mini-coredump-mini-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-debuginfo", rpm: "systemd-mini-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-debugsource", rpm: "systemd-mini-debugsource~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-devel", rpm: "systemd-mini-devel~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-sysvinit", rpm: "systemd-mini-sysvinit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-mini", rpm: "udev-mini~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-mini-debuginfo", rpm: "udev-mini-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-bash-completion", rpm: "systemd-bash-completion~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-bash-completion", rpm: "systemd-mini-bash-completion~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit-debuginfo", rpm: "libsystemd0-32bit-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-devel-32bit", rpm: "libudev-devel-32bit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit-debuginfo", rpm: "libudev1-32bit-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-32bit", rpm: "nss-myhostname-32bit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-32bit-debuginfo", rpm: "nss-myhostname-32bit-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-32bit", rpm: "nss-mymachines-32bit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-32bit-debuginfo", rpm: "nss-mymachines-32bit-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit-debuginfo", rpm: "systemd-32bit-debuginfo~234~lp150.20.15.1", rls: "openSUSELeap15.0" ) )){
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

