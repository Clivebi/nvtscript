if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1487.1" );
	script_cve_id( "CVE-2012-3497", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:31:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1487-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1487-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121487-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2012:1487-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "XEN received various security and bugfixes:

 * CVE-2012-4535: xen: Timer overflow DoS vulnerability
(XSA-20)
 * CVE-2012-4537: xen: Memory mapping failure DoS vulnerability (XSA-22)

The following additional bugs have beenfixed:

 * bnc#784087 - L3: Xen BUG at io_apic.c:129 26102-x86-IOAPIC-legacy-not-first.patch
 * Upstream patches from Jan 25927-x86-domctl-ioport-mapping-range.patch 25931-x86-domctl-iomem-mapping-checks.patch 26061-x86-oprof-counter-range.patch 25431-x86-EDD-MBR-sig-check.patch 25480-x86_64-sysret-canonical.patch 25481-x86_64-AMD-erratum-121.patch 25485-x86_64-canonical-checks.patch 25587-param-parse-limit.patch 25589-pygrub-size-limits.patch 25744-hypercall-return-long.patch 25765-x86_64-allow-unsafe-adjust.patch 25773-x86-honor-no-real-mode.patch 25786-x86-prefer-multiboot-meminfo-over-e801.patch 25808-domain_create-return-value.patch 25814-x86_64-set-debugreg-guest.patch 24742-gnttab-misc.patch 25098-x86-emul-lock-UD.patch 25200-x86_64-trap-bounce-flags.patch 25271-x86_64-IST-index.patch
 *

 bnc#651093 - win2k8 guests are unable to restore after saving the vms state ept-novell-x64.patch 23800-x86_64-guest-addr-range.patch 24168-x86-vioapic-clear-remote_irr.patch 24453-x86-vIRQ-IRR-TMR-race.patch 24456-x86-emul-lea.patch

 *

 bnc#713555 - Unable to install RHEL 6.1 x86 as a paravirtualized guest OS on SLES 10 SP4 x86 vm-install-0.2.19.tar.bz2

Security Issue references:

 * CVE-2012-4539
>
 * CVE-2012-3497
>
 * CVE-2012-4411
>
 * CVE-2012-4535
>
 * CVE-2012-4537
>
 * CVE-2012-4536
>
 * CVE-2012-4538
>
 * CVE-2012-4539
>
 * CVE-2012-4544
>" );
	script_tag( name: "affected", value: "'Xen' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-ps", rpm: "xen-doc-ps~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-ps", rpm: "xen-doc-ps~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-bigsmp", rpm: "xen-kmp-bigsmp~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-debug", rpm: "xen-kmp-debug~3.2.3_17040_42_2.6.16.60_0.99.11~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-debug", rpm: "xen-kmp-debug~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~3.2.3_17040_42_2.6.16.60_0.99.11~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-kdump", rpm: "xen-kmp-kdump~3.2.3_17040_42_2.6.16.60_0.99.11~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-kdump", rpm: "xen-kmp-kdump~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-kdumppae", rpm: "xen-kmp-kdumppae~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-smp", rpm: "xen-kmp-smp~3.2.3_17040_42_2.6.16.60_0.99.11~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-smp", rpm: "xen-kmp-smp~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-vmi", rpm: "xen-kmp-vmi~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-vmipae", rpm: "xen-kmp-vmipae~3.2.3_17040_42_2.6.16.60_0.99.8~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-ioemu", rpm: "xen-tools-ioemu~3.2.3_17040_42~0.7.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-ioemu", rpm: "xen-tools-ioemu~3.2.3_17040_42~0.7.2", rls: "SLES10.0SP4" ) )){
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

