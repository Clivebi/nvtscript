if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3066.2" );
	script_cve_id( "CVE-2017-11624", "CVE-2017-11625", "CVE-2017-11626", "CVE-2017-11627", "CVE-2017-12595", "CVE-2017-9208", "CVE-2017-9209", "CVE-2017-9210" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-08 13:29:00 +0000 (Tue, 08 May 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3066-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3066-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183066-2/" );
	script_xref( name: "URL", value: "http://qpdf.sourceforge.net/files/qpdf-manual.html#ref.release-notes" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qpdf' package(s) announced via the SUSE-SU-2018:3066-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qpdf fixes the following issues:

qpdf was updated to 7.1.1.

Security issues fixed:
CVE-2017-11627: A stack-consumption vulnerability which allows attackers
 to cause DoS (bsc#1050577).

CVE-2017-11625: A stack-consumption vulnerability which allows attackers
 to cause DoS (bsc#1050579).

CVE-2017-11626: A stack-consumption vulnerability which allows attackers
 to cause DoS (bsc#1050578).

CVE-2017-11624: A stack-consumption vulnerability which allows attackers
 to cause DoS (bsc#1050581).

CVE-2017-12595: Stack overflow when processing deeply nested arrays and
 dictionaries (bsc#1055960).

CVE-2017-9209: Remote attackers can cause a denial of service (infinite
 recursion and stack consumption) via a crafted PDF document
 (bsc#1040312).

CVE-2017-9210: Remote attackers can cause a denial of service (infinite
 recursion and stack consumption) via a crafted PDF document
 (bsc#1040313).

CVE-2017-9208: Remote attackers can cause a denial of service (infinite
 recursion and stack consumption) via a crafted PDF document
 (bsc#1040311).

 * Check release notes for detailed bug fixes.
 * [link moved to references]" );
	script_tag( name: "affected", value: "'qpdf' package(s) on SUSE Linux Enterprise Server 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "cups-filters", rpm: "cups-filters~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-cups-browsed", rpm: "cups-filters-cups-browsed~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-cups-browsed-debuginfo", rpm: "cups-filters-cups-browsed-debuginfo~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-debuginfo", rpm: "cups-filters-debuginfo~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-debugsource", rpm: "cups-filters-debugsource~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-foomatic-rip", rpm: "cups-filters-foomatic-rip~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-foomatic-rip-debuginfo", rpm: "cups-filters-foomatic-rip-debuginfo~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-ghostscript", rpm: "cups-filters-ghostscript~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-filters-ghostscript-debuginfo", rpm: "cups-filters-ghostscript-debuginfo~1.0.58~15.2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqpdf18", rpm: "libqpdf18~7.1.1~3.3.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libqpdf18-debuginfo", rpm: "libqpdf18-debuginfo~7.1.1~3.3.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qpdf", rpm: "qpdf~7.1.1~3.3.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qpdf-debuginfo", rpm: "qpdf-debuginfo~7.1.1~3.3.4", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qpdf-debugsource", rpm: "qpdf-debugsource~7.1.1~3.3.4", rls: "SLES12.0SP2" ) )){
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

