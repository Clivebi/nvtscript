if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0860.1" );
	script_cve_id( "CVE-2017-9239", "CVE-2018-17581", "CVE-2019-13110", "CVE-2019-13113", "CVE-2019-17402", "CVE-2019-20421" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-26 17:44:00 +0000 (Wed, 26 Feb 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0860-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0860-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200860-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2020:0860-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for exiv2 fixes the following issues:

CVE-2018-17581: Fixed an excessive stack consumption in
 CiffDirectory:readDirectory() which might have led to denial of service
 (bsc#1110282).

CVE-2019-13110: Fixed an integer overflow and an out of bounds read in
 CiffDirectory:readDirectory which might have led to denial of service
 (bsc#1142678).

CVE-2019-13113: Fixed a potential denial of service via an invalid data
 location in a CRW image (bsc#1142683).

CVE-2019-17402: Fixed an improper validation of the relationship of the
 total size to the offset and size in Exiv2::getULong (bsc#1153577).

CVE-2019-20421: Fixed an infinite loop triggered via an input file
 (bsc#1161901).

CVE-2017-9239: Fixed a segmentation fault in
 TiffImageEntry::doWriteImage function (bsc#1040973)." );
	script_tag( name: "affected", value: "'exiv2' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "exiv2-debuginfo", rpm: "exiv2-debuginfo~0.23~12.8.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exiv2-debugsource", rpm: "exiv2-debugsource~0.23~12.8.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexiv2-12", rpm: "libexiv2-12~0.23~12.8.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexiv2-12-debuginfo", rpm: "libexiv2-12-debuginfo~0.23~12.8.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "exiv2-debuginfo", rpm: "exiv2-debuginfo~0.23~12.8.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "exiv2-debugsource", rpm: "exiv2-debugsource~0.23~12.8.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexiv2-12", rpm: "libexiv2-12~0.23~12.8.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexiv2-12-debuginfo", rpm: "libexiv2-12-debuginfo~0.23~12.8.1", rls: "SLES12.0SP5" ) )){
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

