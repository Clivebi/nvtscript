if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1971.1" );
	script_cve_id( "CVE-2019-12904" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 21:05:00 +0000 (Thu, 04 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1971-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1971-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191971-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt' package(s) announced via the SUSE-SU-2019:1971-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libgcrypt fixes the following issues:

Security issue fixed:
CVE-2019-12904: Fixed a flush-and-reload side-channel attack in the AES
 implementation (bsc#1138939)." );
	script_tag( name: "affected", value: "'libgcrypt' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-debugsource", rpm: "libgcrypt-debugsource~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel", rpm: "libgcrypt-devel~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt-devel-debuginfo", rpm: "libgcrypt-devel-debuginfo~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20", rpm: "libgcrypt20~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-32bit", rpm: "libgcrypt20-32bit~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-32bit-debuginfo", rpm: "libgcrypt20-32bit-debuginfo~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-debuginfo", rpm: "libgcrypt20-debuginfo~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-hmac", rpm: "libgcrypt20-hmac~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcrypt20-hmac-32bit", rpm: "libgcrypt20-hmac-32bit~1.8.2~8.6.2", rls: "SLES15.0SP1" ) )){
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

