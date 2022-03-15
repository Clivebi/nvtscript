if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0779.1" );
	script_cve_id( "CVE-2016-1521", "CVE-2016-1523", "CVE-2016-1526" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0779-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0779-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160779-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphite2' package(s) announced via the SUSE-SU-2016:0779-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for graphite2 fixes the following issues:
- CVE-2016-1521: The directrun function in directmachine.cpp in
 Libgraphite did not validate a certain skip operation, which allowed
 remote attackers to execute arbitrary code, obtain sensitive information,
 or cause a denial of service (out-of-bounds read and application crash)
 via a crafted Graphite smart font.
- CVE-2016-1523: The SillMap::readFace function in FeatureMap.cpp in
 Libgraphite mishandled a return value, which allowed remote attackers to
 cause a denial of service (missing initialization, NULL pointer
 dereference, and application crash) via a crafted Graphite smart font.
- CVE-2016-1526: The TtfUtil:LocaLookup function in TtfUtil.cpp in
 Libgraphite incorrectly validated a size value, which allowed remote
 attackers to obtain sensitive information or cause a denial of service
 (out-of-bounds read and application crash) via a crafted Graphite smart
 font." );
	script_tag( name: "affected", value: "'graphite2' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "graphite2-debuginfo", rpm: "graphite2-debuginfo~1.3.1~6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphite2-debugsource", rpm: "graphite2-debugsource~1.3.1~6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3", rpm: "libgraphite2-3~1.3.1~6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3-32bit", rpm: "libgraphite2-3-32bit~1.3.1~6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3-debuginfo", rpm: "libgraphite2-3-debuginfo~1.3.1~6.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3-debuginfo-32bit", rpm: "libgraphite2-3-debuginfo-32bit~1.3.1~6.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "graphite2-debuginfo", rpm: "graphite2-debuginfo~1.3.1~6.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphite2-debugsource", rpm: "graphite2-debugsource~1.3.1~6.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3", rpm: "libgraphite2-3~1.3.1~6.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3-32bit", rpm: "libgraphite2-3-32bit~1.3.1~6.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3-debuginfo", rpm: "libgraphite2-3-debuginfo~1.3.1~6.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgraphite2-3-debuginfo-32bit", rpm: "libgraphite2-3-debuginfo-32bit~1.3.1~6.1", rls: "SLES12.0SP1" ) )){
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

