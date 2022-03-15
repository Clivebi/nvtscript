if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0302.1" );
	script_cve_id( "CVE-2017-18207", "CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-15903", "CVE-2019-16056", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9947" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 21:14:00 +0000 (Mon, 07 Dec 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0302-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0302-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200302-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python36' package(s) announced via the SUSE-SU-2020:0302-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python36 to version 3.6.10 fixes the following issues:
CVE-2017-18207: Fixed a denial of service in Wave_read._read_fmt_chunk()
 (bsc#1083507).

CVE-2019-16056: Fixed an issue where email parsing could fail for
 multiple @ signs (bsc#1149955).

CVE-2019-15903: Fixed a heap-based buffer over-read in libexpat
 (bsc#1149429)." );
	script_tag( name: "affected", value: "'python36' package(s) on SUSE Linux Enterprise Server 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0", rpm: "libpython3_6m1_0~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython3_6m1_0-debuginfo", rpm: "libpython3_6m1_0-debuginfo~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python36", rpm: "python36~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python36-base", rpm: "python36-base~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python36-base-debuginfo", rpm: "python36-base-debuginfo~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python36-base-debugsource", rpm: "python36-base-debugsource~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python36-debuginfo", rpm: "python36-debuginfo~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python36-debugsource", rpm: "python36-debugsource~3.6.10~4.3.5", rls: "SLES12.0SP5" ) )){
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

