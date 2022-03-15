if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850677" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-09-18 10:31:52 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2013-3495", "CVE-2014-5146", "CVE-2014-5149", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030", "CVE-2014-9065", "CVE-2014-9066", "CVE-2015-0361" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for xen (openSUSE-SU-2015:0256-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The XEN virtualization was updated to fix bugs and security issues:

  Security issues fixed: CVE-2015-0361: XSA-116: xen: xen crash due to use
  after free on hvm guest teardown

  CVE-2014-9065, CVE-2014-9066: XSA-114: xen: p2m lock starvation

  CVE-2014-9030: XSA-113: Guest effectable page reference leak in
  MMU_MACHPHYS_UPDATE handling

  CVE-2014-8867: XSA-112: xen: Insufficient bounding of 'REP MOVS' to MMIO
  emulated inside the hypervisor

  CVE-2014-8866: XSA-111: xen: Excessive checking in compatibility mode
  hypercall argument translation

  CVE-2014-8595: XSA-110: xen: Missing privilege level checks in x86
  emulation of far branches

  CVE-2014-8594: XSA-109: xen: Insufficient restrictions on certain MMU
  update hypercalls

  CVE-2013-3495: XSA-59: xen: Intel VT-d Interrupt Remapping engines can be
  evaded by native NMI interrupts

  CVE-2014-5146, CVE-2014-5149: xen: XSA-97 Long latency virtual-mmu
  operations are not preemptible

  Bugs fixed:

  - Restore missing fixes from block-dmmd script

  - bnc#904255 - XEN boot hangs in early boot on UEFI system

  - Fix missing banner by restoring figlet program

  - bnc#903357 - Corrupted save/restore test leaves orphaned data in xenstore

  - bnc#903359 - Temporary migration name is not cleaned up after migration

  - bnc#903850 - Xen: guest user mode triggerable VM exits not handled by
  hypervisor

  - bnc#866902 - Xen save/restore of HVM guests cuts off disk and networking

  - bnc#901317 - increase limit domUloader to 32MB

  - bnc#898772 - SLES 12 RC3 - XEN Host crashes when assigning non-VF device
  (SR-IOV) to guest

  - bnc#882089 - Windows 2012 R2 fails to boot up with greater than 60 vcpus

  - bsc#900292 - xl: change default dump directory

  - Update xen2libvirt.py to better detect and handle file formats

  - bnc#882089 - Windows 2012 R2 fails to boot up with greater than 60 vcpus


  - bnc#897906 - libxc: check return values on mmap() and madvise()
  on xc_alloc_hypercall_buffer()

  - bnc#896023 - Adjust xentop column layout" );
	script_tag( name: "affected", value: "xen on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0256-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.4.1_08_k3.16.7_7~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default-debuginfo", rpm: "xen-kmp-default-debuginfo~4.4.1_08_k3.16.7_7~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-desktop", rpm: "xen-kmp-desktop~4.4.1_08_k3.16.7_7~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-desktop-debuginfo", rpm: "xen-kmp-desktop-debuginfo~4.4.1_08_k3.16.7_7~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.4.1_08~9.1", rls: "openSUSE13.2" ) )){
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

