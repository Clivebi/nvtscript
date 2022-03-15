if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1132.1" );
	script_cve_id( "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3498", "CVE-2012-3515" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-11 15:21:00 +0000 (Tue, 11 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1132-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1132-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121132-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2012:1132-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "XEN was updated 4.1.3 to fix multiple bugs and security issues.

The following security issues have been fixed:

 * CVE-2012-3494: xen: hypercall set_debugreg vulnerability (XSA-12)
 * CVE-2012-3495: xen: hypercall physdev_get_free_pirq vulnerability (XSA-13)
 * CVE-2012-3496: xen: XENMEM_populate_physmap DoS vulnerability (XSA-14)
 * CVE-2012-3498: xen: PHYSDEVOP_map_pirq index vulnerability (XSA-16)
 * CVE-2012-3515: xen: Qemu VT100 emulation vulnerability (XSA-17)

Also the following bugs have been fixed:

 * pvscsi support of attaching Luns - bnc#776995

The following related bugs in vm-install 0.5.12 have been fixed:

 * bnc#776300 - vm-install does not pass --extra-args in
--upgrade
 * Add for support Open Enterprise Server 11
 * Add support for Windows 8 and Windows Server 2012
 * Add support for Ubuntu 12 (Precise Pangolin)

Security Issue references:

 * CVE-2012-3496
>
 * CVE-2012-3494
>
 * CVE-2012-3495
>
 * CVE-2012-3498
>
 * CVE-2012-3515
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
	if(!isnull( res = isrpmvuln( pkg: "vm-install", rpm: "vm-install~0.5.12~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "vm-install", rpm: "vm-install~0.5.12~0.5.3", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.1.3_02_3.0.38_0.5~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-trace", rpm: "xen-kmp-trace~4.1.3_02_3.0.38_0.5~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.1.3_02~0.5.1", rls: "SLES11.0SP2" ) )){
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

