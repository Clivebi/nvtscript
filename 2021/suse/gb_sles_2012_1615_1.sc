if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1615.1" );
	script_cve_id( "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:32:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1615-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1615-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121615-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2012:1615-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following security issues in xen:

 * CVE-2012-5510: Grant table version switch list corruption vulnerability (XSA-26)
 * CVE-2012-5511: Several HVM operations do not validate the range of their inputs (XSA-27)
 * CVE-2012-5512: HVMOP_get_mem_access crash /
HVMOP_set_mem_access information leak (XSA-28)
 * CVE-2012-5513: XENMEM_exchange may overwrite hypervisor memory (XSA-29)
 * CVE-2012-5514: Missing unlock in guest_physmap_mark_populate_on_demand() (XSA-30)
 * CVE-2012-5515: Several memory hypercall operations allow invalid extent order values (XSA-31)

Also the following bugs have been fixed and upstream patches have been applied:

 * FATAL PAGE FAULT in hypervisor (arch_do_domctl)
 * 25931-x86-domctl-iomem-mapping-checks.patch
 * 26132-tmem-save-NULL-check.patch
 * 26134-x86-shadow-invlpg-check.patch
 * 26148-vcpu-timer-overflow.patch (Replaces CVE-2012-4535-xsa20.patch)
 * 26149-x86-p2m-physmap-error-path.patch (Replaces CVE-2012-4537-xsa22.patch)
 * 26150-x86-shadow-unhook-toplevel-check.patch
(Replaces CVE-2012-4538-xsa23.patch)
 * 26151-gnttab-compat-get-status-frames.patch (Replaces CVE-2012-4539-xsa24.patch)
 * bnc#792476 - efi files missing in latest XEN update

Security Issue references:

 * CVE-2012-5512
>
 * CVE-2012-5513
>
 * CVE-2012-5514
>
 * CVE-2012-5511
>
 * CVE-2012-5510
>
 * CVE-2012-5515
>" );
	script_tag( name: "affected", value: "'Xen' package(s) on SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.1.3_06_3.0.51_0.7.9~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-trace", rpm: "xen-kmp-trace~4.1.3_06_3.0.51_0.7.9~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.1.3_06~0.7.1", rls: "SLES11.0SP2" ) )){
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

