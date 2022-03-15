if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1767.1" );
	script_cve_id( "CVE-2019-15666", "CVE-2020-10757" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-15 15:15:00 +0000 (Tue, 15 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1767-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1767-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201767-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 31 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2020:1767-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.121-92_117 fixes several issues.

The following security issues were fixed:

CVE-2020-10757: Fixed an issue where remaping hugepage DAX to anon mmap
 could have caused user PTE access (bsc#1172437).

CVE-2019-15666: Fixed an out of bounds read __xfrm_policy_unlink, which
 could have led to denial of service (bsc#1172140)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 31 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_114-default", rpm: "kgraft-patch-4_4_121-92_114-default~10~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_117-default", rpm: "kgraft-patch-4_4_121-92_117-default~9~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_120-default", rpm: "kgraft-patch-4_4_121-92_120-default~8~2.1", rls: "SLES12.0SP2" ) )){
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

