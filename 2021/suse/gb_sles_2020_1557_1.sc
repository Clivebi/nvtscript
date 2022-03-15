if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1557.1" );
	script_cve_id( "CVE-2019-16680", "CVE-2020-11736" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:02 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-20 17:23:00 +0000 (Fri, 20 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1557-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1557-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201557-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'file-roller' package(s) announced via the SUSE-SU-2020:1557-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for file-roller fixes the following issues:

CVE-2020-11736: Fixed a directory traversal vulnerability due to
 improper checking whether a file's parent is an external symlink
 (bsc#1169428).

CVE-2019-16680: Fixed a path traversal vulnerability which could have
 allowed an overwriting of a file during extraction (bsc#1151585)." );
	script_tag( name: "affected", value: "'file-roller' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP1." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "file-roller", rpm: "file-roller~3.26.2~4.5.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-roller-debuginfo", rpm: "file-roller-debuginfo~3.26.2~4.5.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-roller-debugsource", rpm: "file-roller-debugsource~3.26.2~4.5.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-roller-lang", rpm: "file-roller-lang~3.26.2~4.5.1", rls: "SLES15.0SP1" ) )){
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

