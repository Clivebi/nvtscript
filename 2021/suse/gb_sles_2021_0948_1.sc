if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0948.1" );
	script_cve_id( "CVE-2021-24031", "CVE-2021-24032" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:41 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 15:28:00 +0000 (Wed, 14 Apr 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0948-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0948-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210948-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zstd' package(s) announced via the SUSE-SU-2021:0948-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for zstd fixes the following issues:

CVE-2021-24031: Added read permissions to files while being compressed
 or uncompressed (bsc#1183371).

CVE-2021-24032: Fixed a race condition which could have allowed an
 attacker to access world-readable destination file (bsc#1183370)." );
	script_tag( name: "affected", value: "'zstd' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE MicroOS 5.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libzstd-devel", rpm: "libzstd-devel~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzstd1", rpm: "libzstd1~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzstd1-32bit", rpm: "libzstd1-32bit~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzstd1-32bit-debuginfo", rpm: "libzstd1-32bit-debuginfo~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzstd1-debuginfo", rpm: "libzstd1-debuginfo~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zstd", rpm: "zstd~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zstd-debuginfo", rpm: "zstd-debuginfo~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zstd-debugsource", rpm: "zstd-debugsource~1.4.4~1.6.1", rls: "SLES15.0SP2" ) )){
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

