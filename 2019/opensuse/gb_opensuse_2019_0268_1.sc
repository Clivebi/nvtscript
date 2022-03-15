if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852325" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-6454" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-03-01 04:15:17 +0100 (Fri, 01 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for systemd (openSUSE-SU-2019:0268-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0268-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00075.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2019:0268-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for systemd fixes the following issues:

  Security vulnerability fixed:

  - CVE-2019-6454: Fixed a crash of PID1 by sending specially crafted D-BUS
  message on the system bus by an unprivileged user (bsc#1125352)

  Other bug fixes and changes:

  - journal-remote: set a limit on the number of fields in a message

  - journal-remote: verify entry length from header

  - journald: set a limit on the number of fields (1k)

  - journald: do not store the iovec entry for process commandline on stack

  - core: include Found state in device dumps

  - device: fix serialization and deserialization of DeviceFound

  - fix path in btrfs rule (#6844)

  - assemble multidevice btrfs volumes without external tools (#6607)
  (bsc#1117025)

  - Update systemd-system.conf.xml (bsc#1122000)

  - units: inform user that the default target is started after exiting from
  rescue or emergency mode

  - manager: don't skip sigchld handler for main and control pid for
  services (#3738)

  - core: Add helper functions unit_{main, control}_pid

  - manager: Fixing a debug printf formatting mistake (#3640)

  - manager: Only invoke a single sigchld per unit within a cleanup cycle
  (bsc#1117382)

  - core: update invoke_sigchld_event() to handle NULL - sigchld_event()

  - sd-event: expose the event loop iteration counter via
  sd_event_get_iteration() (#3631)

  - unit: rework a bit how we keep the service fdstore from being destroyed
  during service restart (bsc#1122344)

  - core: when restarting services, don't close fds

  - cryptsetup: Add dependency on loopback setup to generated units

  - journal-gateway: use localStorage['cursor'] only when it has valid value

  - journal-gateway: explicitly declare local variables

  - analyze: actually select longest activated-time of services

  - sd-bus: fix implicit downcast of bitfield reported by LGTM

  - core: free lines after reading them (bsc#1123892)

  - pam_systemd: reword message about not creating a session (bsc#1111498)

  - pam_systemd: suppress LOG_DEBUG log messages if debugging is off
  (bsc#1111498)

  - main: improve RLIMIT_NOFILE handling (#5795) (bsc#1120658)

  - sd-bus: if we receive an invalid dbus message, ignore and proceed

  - automount: don't pass non-blocking pipe to kernel.

  - units: make sure initrd-cleanup.service terminates before switching to
  rootfs (bsc#1123333)

  - units: add Wants=initrd-cleanup.service to initrd-switch-root.target
  (#4345) (bsc#1123333)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  insta ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "systemd on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-mini", rpm: "libsystemd0-mini~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-mini-debuginfo", rpm: "libsystemd0-mini-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-devel", rpm: "libudev-devel~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-mini-devel", rpm: "libudev-mini-devel~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-mini1", rpm: "libudev-mini1~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-mini1-debuginfo", rpm: "libudev-mini1-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname", rpm: "nss-myhostname~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-debuginfo", rpm: "nss-myhostname-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines", rpm: "nss-mymachines~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-debuginfo", rpm: "nss-mymachines-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-devel", rpm: "systemd-devel~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-logger", rpm: "systemd-logger~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini", rpm: "systemd-mini~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-debuginfo", rpm: "systemd-mini-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-debugsource", rpm: "systemd-mini-debugsource~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-devel", rpm: "systemd-mini-devel~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-sysvinit", rpm: "systemd-mini-sysvinit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-mini", rpm: "udev-mini~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-mini-debuginfo", rpm: "udev-mini-debuginfo~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo-32bit", rpm: "libsystemd0-debuginfo-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo-32bit", rpm: "libudev1-debuginfo-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-32bit", rpm: "nss-myhostname-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-debuginfo-32bit", rpm: "nss-myhostname-debuginfo-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo-32bit", rpm: "systemd-debuginfo-32bit~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-bash-completion", rpm: "systemd-bash-completion~228~68.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-mini-bash-completion", rpm: "systemd-mini-bash-completion~228~68.1", rls: "openSUSELeap42.3" ) )){
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

