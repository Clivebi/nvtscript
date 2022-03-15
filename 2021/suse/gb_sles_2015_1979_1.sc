if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1979.1" );
	script_cve_id( "CVE-2014-9756", "CVE-2015-7805" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1979-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1979-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151979-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsndfile' package(s) announced via the SUSE-SU-2015:1979-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The libsndfile package was updated to fix the following security issue:
- CVE-2014-9756: Fixed a divide by zero problem that can lead to a Denial
 of Service (DoS) (bsc#953521).
- CVE-2015-7805: Fixed heap overflow issue (bsc#953516)." );
	script_tag( name: "affected", value: "'libsndfile' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for VMWare 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsndfile", rpm: "libsndfile~1.0.20~2.10.2", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-32bit", rpm: "libsndfile-32bit~1.0.20~2.10.2", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-x86", rpm: "libsndfile-x86~1.0.20~2.10.2", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libsndfile", rpm: "libsndfile~1.0.20~2.10.2", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-32bit", rpm: "libsndfile-32bit~1.0.20~2.10.2", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsndfile-x86", rpm: "libsndfile-x86~1.0.20~2.10.2", rls: "SLES11.0SP4" ) )){
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

