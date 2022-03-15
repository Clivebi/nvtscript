if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2444.1" );
	script_cve_id( "CVE-2019-15142", "CVE-2019-15143", "CVE-2019-15144", "CVE-2019-15145" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 16:40:00 +0000 (Thu, 27 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2444-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2444-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192444-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'djvulibre' package(s) announced via the SUSE-SU-2019:2444-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for djvulibre fixes the following issues:

Security issues fixed:
CVE-2019-15142: Fixed heap-based buffer over-read (bsc#1146702).

CVE-2019-15143: Fixed resource exhaustion caused by corrupted image
 files (bsc#1146569).

CVE-2019-15144: Fixed denial-of-service caused by crafted PBM image
 files (bsc#1146571).

CVE-2019-15145: Fixed out-of-bounds read caused by corrupted JB2 image
 files (bsc#1146572).

Fixed segfault when libtiff encounters corrupted TIFF (upstream issue
 #295)." );
	script_tag( name: "affected", value: "'djvulibre' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "djvulibre-debuginfo", rpm: "djvulibre-debuginfo~3.5.25.3~5.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "djvulibre-debugsource", rpm: "djvulibre-debugsource~3.5.25.3~5.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre21", rpm: "libdjvulibre21~3.5.25.3~5.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdjvulibre21-debuginfo", rpm: "libdjvulibre21-debuginfo~3.5.25.3~5.3.1", rls: "SLES12.0SP4" ) )){
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

