if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854050" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-21781", "CVE-2021-22543", "CVE-2021-3659", "CVE-2021-3679", "CVE-2021-37576" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-05 18:09:00 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 03:02:10 +0000 (Wed, 11 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for the (openSUSE-SU-2021:1142-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1142-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BN7VVRY72WW4I46CQCFBKXWN6CBHKRXO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2021:1142-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The openSUSE Leap 15.2 kernel was updated to receive various security and
     bugfixes.

     The following security bugs were fixed:

  - CVE-2021-3679: A lack of CPU resource in the Linux kernel tracing module
       functionality was found in the way user uses trace ring buffer in a
       specific way. Only privileged local users (with CAP_SYS_ADMIN
       capability) could use this flaw to starve the resources causing denial
       of service (bnc#1189057).

  - CVE-2021-3659: Fix general protection fault via NULL pointer dereference
       in llsec_key_alloc() in net/mac802154/llsec.c (bsc#1188876).

  - CVE-2021-37576: arch/powerpc/kvm/book3s_rtas.c on the powerpc platform
       allowed KVM guest OS users to cause host OS memory corruption via
       rtas_args.nargs, aka CID-f62f3c20647e (bnc#1188838 bnc#1188842).

  - CVE-2021-22543: KVM through Improper handling of VM_IOVM_PFNMAP vmas in
       KVM could bypass RO checks and can lead to pages being freed while still
       accessible by the VMM and guest. This allowed users with the ability to
       start and control a VM to read/write random pages of memory and can
       result in local privilege escalation (bnc#1186482).

  - CVE-2021-21781: A SIGPAGE information disclosure vulnerability on ARM
       was fixed (bsc#1188445).

     The following non-security bugs were fixed:

  - ACPI: AMBA: Fix resource name in /proc/iomem (git-fixes).

  - ACPI: video: Add quirk for the Dell Vostro 3350 (git-fixes).

  - ALSA: ac97: fix PM reference leak in ac97_bus_remove() (git-fixes).

  - ALSA: bebob: add support for ToneWeal FW66 (git-fixes).

  - ALSA: hda: Add IRQ check for platform_get_irq() (git-fixes).

  - ALSA: hda/realtek: add mic quirk for Acer SF314-42 (git-fixes).

  - ALSA: hda/realtek: Fix headset mic for Acer SWIFT SF314-56 (ALC256)
       (git-fixes).

  - ALSA: hdmi: Expose all pins on MSI MS-7C94 board (git-fixes).

  - ALSA: ppc: fix error return code in snd_pmac_probe() (git-fixes).

  - ALSA: sb: Fix potential ABBA deadlock in CSP driver (git-fixes).

  - ALSA: sb: Fix potential double-free of CSP mixer elements (git-fixes).

  - ALSA: seq: Fix racy deletion of subscriber (git-fixes).

  - ALSA: usb-audio: Add registration quirk for JBL Quantum 600 (git-fixes).

  - ALSA: usb-audio: Add registration quirk for JBL Quantum headsets
       (git-fixes).

  - ALSA: usb-audio: Fix superfluous autosuspend recovery (git-fixes).

  - ALSA: usb-audio: scarlett2: Fix 18i8 Gen 2 PCM Input count (git-fixes).

  - ALSA: usb-audio: scarlett2: Fix 6i6 Gen 2 line out descriptions
     ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'the' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs-html", rpm: "kernel-docs-html~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-vanilla", rpm: "kernel-source-vanilla~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debugsource", rpm: "kernel-debug-debugsource~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel-debuginfo", rpm: "kernel-debug-devel-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~5.3.18~lp152.87.1.lp152.8.40.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-rebuild", rpm: "kernel-default-base-rebuild~5.3.18~lp152.87.1.lp152.8.40.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kvmsmall", rpm: "kernel-kvmsmall~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kvmsmall-debuginfo", rpm: "kernel-kvmsmall-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kvmsmall-debugsource", rpm: "kernel-kvmsmall-debugsource~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kvmsmall-devel", rpm: "kernel-kvmsmall-devel~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kvmsmall-devel-debuginfo", rpm: "kernel-kvmsmall-devel-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-qa", rpm: "kernel-obs-qa~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt", rpm: "kernel-preempt~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-debuginfo", rpm: "kernel-preempt-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-debugsource", rpm: "kernel-preempt-debugsource~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-devel", rpm: "kernel-preempt-devel~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-devel-debuginfo", rpm: "kernel-preempt-devel-debuginfo~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~5.3.18~lp152.87.1", rls: "openSUSELeap15.2" ) )){
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

