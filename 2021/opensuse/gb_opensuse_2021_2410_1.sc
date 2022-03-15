if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854003" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-33910" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-29 17:50:00 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-21 03:02:29 +0000 (Wed, 21 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for systemd (openSUSE-SU-2021:2410-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2410-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IPIXUFHECPYFYLXDFG3MHBODZD7H7P2I" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2021:2410-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for systemd fixes the following issues:

  - CVE-2021-33910: Fixed a denial of service (stack exhaustion) in systemd
       (PID 1)  (bsc#1188063)" );
	script_tag( name: "affected", value: "'systemd' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0", rpm: "libsystemd0~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-debuginfo", rpm: "libsystemd0-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-devel", rpm: "libudev-devel~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1", rpm: "libudev1~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-debuginfo", rpm: "libudev1-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname", rpm: "nss-myhostname~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-debuginfo", rpm: "nss-myhostname-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines", rpm: "nss-mymachines~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-debuginfo", rpm: "nss-mymachines-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-resolve", rpm: "nss-resolve~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-resolve-debuginfo", rpm: "nss-resolve-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-systemd", rpm: "nss-systemd~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-systemd-debuginfo", rpm: "nss-systemd-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd", rpm: "systemd~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-container", rpm: "systemd-container~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-container-debuginfo", rpm: "systemd-container-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-coredump", rpm: "systemd-coredump~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-coredump-debuginfo", rpm: "systemd-coredump-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debuginfo", rpm: "systemd-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-debugsource", rpm: "systemd-debugsource~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-devel", rpm: "systemd-devel~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-doc", rpm: "systemd-doc~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-journal-remote", rpm: "systemd-journal-remote~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-journal-remote-debuginfo", rpm: "systemd-journal-remote-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-logger", rpm: "systemd-logger~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-network", rpm: "systemd-network~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-network-debuginfo", rpm: "systemd-network-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-sysvinit", rpm: "systemd-sysvinit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev", rpm: "udev~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udev-debuginfo", rpm: "udev-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-lang", rpm: "systemd-lang~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit", rpm: "libsystemd0-32bit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsystemd0-32bit-debuginfo", rpm: "libsystemd0-32bit-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev-devel-32bit", rpm: "libudev-devel-32bit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit", rpm: "libudev1-32bit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libudev1-32bit-debuginfo", rpm: "libudev1-32bit-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-32bit", rpm: "nss-myhostname-32bit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-myhostname-32bit-debuginfo", rpm: "nss-myhostname-32bit-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-32bit", rpm: "nss-mymachines-32bit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-mymachines-32bit-debuginfo", rpm: "nss-mymachines-32bit-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit", rpm: "systemd-32bit~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "systemd-32bit-debuginfo", rpm: "systemd-32bit-debuginfo~246.13~7.8.1", rls: "openSUSELeap15.3" ) )){
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

