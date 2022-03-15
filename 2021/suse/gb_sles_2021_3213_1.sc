if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3213.1" );
	script_cve_id( "CVE-2021-28701" );
	script_tag( name: "creation_date", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_version( "2021-09-24T07:14:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-16 21:15:00 +0000 (Thu, 16 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3213-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3213-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213213-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2021:3213-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:

CVE-2021-28701: Fixed race condition in XENMAPSPACE_grant_table handling
 (XSA-384) (bsc#1189632).

Integrate bugfixes (bsc#1189373, bsc#1189378)." );
	script_tag( name: "affected", value: "'xen' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.9.4_22~3.94.2", rls: "SLES12.0SP3" ) )){
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

