if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0438.1" );
	script_cve_id( "CVE-2019-3827" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-19 18:06:00 +0000 (Mon, 19 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0438-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0438-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190438-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gvfs' package(s) announced via the SUSE-SU-2019:0438-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gvfs fixes the following issues:

Security vulnerability fixed:
CVE-2019-3827: Fixed an issue whereby an unprivileged user was not
 prompted to give a password when acessing root owned files. (bsc#1125084)" );
	script_tag( name: "affected", value: "'gvfs' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "gvfs", rpm: "gvfs~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-backend-afc", rpm: "gvfs-backend-afc~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-backend-afc-debuginfo", rpm: "gvfs-backend-afc-debuginfo~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-backend-samba", rpm: "gvfs-backend-samba~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-backend-samba-debuginfo", rpm: "gvfs-backend-samba-debuginfo~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-backends", rpm: "gvfs-backends~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-backends-debuginfo", rpm: "gvfs-backends-debuginfo~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-debuginfo", rpm: "gvfs-debuginfo~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-debugsource", rpm: "gvfs-debugsource~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-devel", rpm: "gvfs-devel~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-fuse", rpm: "gvfs-fuse~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-fuse-debuginfo", rpm: "gvfs-fuse-debuginfo~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gvfs-lang", rpm: "gvfs-lang~1.34.2.1~4.6.1", rls: "SLES15.0" ) )){
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

