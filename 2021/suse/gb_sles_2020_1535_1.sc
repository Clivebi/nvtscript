if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1535.1" );
	script_cve_id( "CVE-2017-8834", "CVE-2017-8871" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:02 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-19 19:17:00 +0000 (Wed, 19 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1535-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1535-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201535-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libcroco' package(s) announced via the SUSE-SU-2020:1535-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libcroco fixes the following issues:

Security issues fixed:

CVE-2017-8834: Fixed denial of service (memory allocation error) via a
 crafted CSS file (bsc#1043898).

CVE-2017-8871: Fixed denial of service (infinite loop and CPU
 consumption) via a crafted CSS file (bsc#1043899)." );
	script_tag( name: "affected", value: "'libcroco' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libcroco", rpm: "libcroco~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-0_6-3", rpm: "libcroco-0_6-3~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-0_6-3-32bit", rpm: "libcroco-0_6-3-32bit~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-0_6-3-32bit-debuginfo", rpm: "libcroco-0_6-3-32bit-debuginfo~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-0_6-3-debuginfo", rpm: "libcroco-0_6-3-debuginfo~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-debuginfo", rpm: "libcroco-debuginfo~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-debugsource", rpm: "libcroco-debugsource~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcroco-devel", rpm: "libcroco-devel~0.6.12~4.3.51", rls: "SLES15.0SP1" ) )){
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

