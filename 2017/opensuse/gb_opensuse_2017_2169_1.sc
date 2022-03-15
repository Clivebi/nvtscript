if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851594" );
	script_version( "2021-09-15T14:07:14+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 14:07:14 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-16 07:33:43 +0200 (Wed, 16 Aug 2017)" );
	script_cve_id( "CVE-2017-1000111", "CVE-2017-1000112", "CVE-2017-8831" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for kernel (openSUSE-SU-2017:2169-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The openSUSE Leap 42.2 kernel was updated to receive various security and
  bugfixes.

  The following security bugs were fixed:

  - CVE-2017-1000111: Fixed a race condition in net-packet code that could
  be exploited to cause out-of-bounds memory access (bsc#1052365).

  - CVE-2017-1000112: Fixed a race condition in net-packet code that could
  have been exploited by unprivileged users to gain root access.
  (bsc#1052311).

  - CVE-2017-8831: The saa7164_bus_get function in
  drivers/media/pci/saa7164/saa7164-bus.c in the Linux kernel allowed
  local users to cause a denial of service (out-of-bounds array access) or
  possibly have unspecified other impact by changing a certain
  sequence-number value, aka a 'double fetch' vulnerability (bnc#1037994).

  The following non-security bugs were fixed:

  - IB/hfi1: Wait for QSFP modules to initialize (bsc#1019151).

  - bcache: force trigger gc (bsc#1038078).

  - bcache: only recovery I/O error for writethrough mode (bsc#1043652).

  - block: do not allow updates through sysfs until registration completes
  (bsc#1047027).

  - ibmvnic: Check for transport event on driver resume (bsc#1051556,
  bsc#1052709).

  - ibmvnic: Initialize SCRQ's during login renegotiation (bsc#1052223).

  - ibmvnic: Report rx buffer return codes as netdev_dbg (bsc#1052794).

  - iommu/amd: Fix schedule-while-atomic BUG in initialization code
  (bsc1052533).

  - libnvdimm, pmem: fix a NULL pointer BUG in nd_pmem_notify (bsc#1023175).

  - libnvdimm: fix badblock range handling of ARS range (bsc#1023175).

  - qeth: fix L3 next-hop im xmit qeth hdr (bnc#1052773, LTC#157374).

  - scsi_devinfo: fixup string compare (bsc#1037404).

  - scsi_dh_alua: suppress errors from unsupported devices (bsc#1038792).

  - vfs: fix missing inode_get_dev sites (bsc#1052049).

  - x86/dmi: Switch dmi_remap() from ioremap() to ioremap_cache()
  (bsc#1051399)." );
	script_tag( name: "affected", value: "Linux Kernel on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2169-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-base", rpm: "kernel-debug-base~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-base-debuginfo", rpm: "kernel-debug-base-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debugsource", rpm: "kernel-debug-debugsource~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel-debuginfo", rpm: "kernel-debug-devel-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-qa", rpm: "kernel-obs-qa~4.4.79~18.26.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.79~18.26.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla", rpm: "kernel-vanilla~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-base", rpm: "kernel-vanilla-base~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-base-debuginfo", rpm: "kernel-vanilla-base-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debuginfo", rpm: "kernel-vanilla-debuginfo~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debugsource", rpm: "kernel-vanilla-debugsource~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-devel", rpm: "kernel-vanilla-devel~4.4.79~18.26.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.79~18.26.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~4.4.79~18.26.3", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs-html", rpm: "kernel-docs-html~4.4.79~18.26.3", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs-pdf", rpm: "kernel-docs-pdf~4.4.79~18.26.3", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.79~18.26.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.79~18.26.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-vanilla", rpm: "kernel-source-vanilla~4.4.79~18.26.1", rls: "openSUSELeap42.2" ) )){
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

