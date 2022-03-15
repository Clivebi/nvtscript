if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851512" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-22 15:18:41 +0100 (Wed, 22 Feb 2017)" );
	script_cve_id( "CVE-2016-9576" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for kernel (openSUSE-SU-2016:3085-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The openSUSE 14.2 kernel was updated to receive various security and
  bugfixes.

  The following security bugs were fixed:

  - CVE-2016-9576: A use-after-free vulnerability in the SCSI generic driver
  allows users with write access to /dev/sg* or /dev/bsg* to elevate their
  privileges (bsc#1013604).

  The following non-security bugs were fixed:

  - 8250_pci: Fix potential use-after-free in error path (bsc#1013001).

  - block_dev: do not test bdev-&amp gt bd_contains when it is not stable
  (bsc#1008557).

  - drm/i915/vlv: Disable HPD in valleyview_crt_detect_hotplug()
  (bsc#1014120).

  - drm/i915/vlv: Make intel_crt_reset() per-encoder (bsc#1014120).

  - drm/i915/vlv: Reset the ADPA in vlv_display_power_well_init()
  (bsc#1014120).

  - drm/i915: Enable polling when we do not have hpd (bsc#1014120).

  - i2c: designware-baytrail: Add support for cherrytrail (bsc#1011913).

  - i2c: designware-baytrail: Pass dw_i2c_dev into helper functions
  (bsc#1011913).

  - i2c: designware: Prevent runtime suspend during adapter registration
  (bsc#1011913).

  - i2c: designware: Use transfer timeout from ioctl I2C_TIMEOUT
  (bsc#1011913).

  - i2c: designware: retry transfer on transient failure (bsc#1011913).

  - powerpc/xmon: Add xmon command to dump process/task similar to ps(1)
  (fate#322020).

  - sched/fair: Fix incorrect task group -&amp gt load_avg (bsc#981825).

  - serial: 8250_pci: Detach low-level driver during PCI error recovery
  (bsc#1013001).

  - target: fix tcm_rbd_gen_it_nexus for emulated XCOPY state (bsc#1003606).

  - x86/PCI: VMD: Synchronize with RCU freeing MSI IRQ descs (bsc#1006827)." );
	script_tag( name: "affected", value: "Linux Kernel on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:3085-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-base", rpm: "kernel-debug-base~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-base-debuginfo", rpm: "kernel-debug-base-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debugsource", rpm: "kernel-debug-debugsource~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel-debuginfo", rpm: "kernel-debug-devel-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-qa", rpm: "kernel-obs-qa~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla", rpm: "kernel-vanilla~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-base", rpm: "kernel-vanilla-base~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-base-debuginfo", rpm: "kernel-vanilla-base-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debuginfo", rpm: "kernel-vanilla-debuginfo~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debugsource", rpm: "kernel-vanilla-debugsource~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-devel", rpm: "kernel-vanilla-devel~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~4.4.36~8.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs-html", rpm: "kernel-docs-html~4.4.36~8.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs-pdf", rpm: "kernel-docs-pdf~4.4.36~8.2", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-vanilla", rpm: "kernel-source-vanilla~4.4.36~8.1", rls: "openSUSELeap42.2" ) )){
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

