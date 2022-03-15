if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1652.1" );
	script_cve_id( "CVE-2014-9112" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1652-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1652-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141652-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cpio' package(s) announced via the SUSE-SU-2014:1652-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This cpio security update fixes the following buffer overflow issue and two non security issues:

- fix an OOB write with cpio -i (bnc#907456) (CVE-2014-9112)
- prevent cpio from extracting over a symlink (bnc#658010)
- fix a truncation check in mt" );
	script_tag( name: "affected", value: "'cpio' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "cpio", rpm: "cpio~2.11~29.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-debuginfo", rpm: "cpio-debuginfo~2.11~29.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-debugsource", rpm: "cpio-debugsource~2.11~29.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cpio-lang", rpm: "cpio-lang~2.11~29.1", rls: "SLES12.0" ) )){
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
