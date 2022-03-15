if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1314.1" );
	script_cve_id( "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2014-12-12 02:59:00 +0000 (Fri, 12 Dec 2014)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1314-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1314-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131314-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2013:1314-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Xen hypervisor and toolset has been updated to 4.2.2_06 to fix various bugs and security issues:

The following security issues have been addressed:

 * CVE-2013-2194: Various integer overflows in the ELF loader were fixed. (XSA-55)
 * CVE-2013-2195: Various pointer dereferences issues in the ELF loader were fixed. (XSA-55)
 * CVE-2013-2196: Various other problems in the ELF loader were fixed. (XSA-55)
 * CVE-2013-2078: A Hypervisor crash due to missing exception recovery on XSETBV was fixed. (XSA-54)
 * CVE-2013-2077: A Hypervisor crash due to missing exception recovery on XRSTOR was fixed. (XSA-53)
 * CVE-2013-2211: libxl allowed guest write access to sensitive console related xenstore keys. (XSA-57)
 * CVE-2013-2076: An information leak on XSAVE/XRSTOR capable AMD CPUs (XSA-52) was fixed, where parts of this state could leak to other VMs.

Also the following bugs have been fixed:

 * performance issues in mirror lvm (bnc#801663)
 * aacraid driver panics mapping INT A when booting kernel-xen (bnc#808085)
 * Fully Virtualized Windows VM install failed on Ivy Bridge platforms with Xen kernel (bnc#808269)
 * Did not boot with i915 graphics controller with VT-d enabled (bnc#817210)

Security Issue references:

 * CVE-2013-2194
>
 * CVE-2013-2195
>
 * CVE-2013-2196
>" );
	script_tag( name: "affected", value: "'Xen' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.2.2_06_3.0.82_0.7~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-pae", rpm: "xen-kmp-pae~4.2.2_06_3.0.82_0.7~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.2.2_06~0.7.1", rls: "SLES11.0SP3" ) )){
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

