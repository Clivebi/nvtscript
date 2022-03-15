if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1195.1" );
	script_cve_id( "CVE-2017-9814" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 21:09:00 +0000 (Thu, 04 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1195-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1195-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181195-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cairo' package(s) announced via the SUSE-SU-2018:1195-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cairo fixes the following issues:
 - CVE-2017-9814: out-of-bounds read in cairo-truetype-subset.c could
 lead to denial of service (bsc#1049092)." );
	script_tag( name: "affected", value: "'cairo' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "cairo-debugsource", rpm: "cairo-debugsource~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo-gobject2", rpm: "libcairo-gobject2~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo-gobject2-32bit", rpm: "libcairo-gobject2-32bit~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo-gobject2-debuginfo", rpm: "libcairo-gobject2-debuginfo~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo-gobject2-debuginfo-32bit", rpm: "libcairo-gobject2-debuginfo-32bit~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo-script-interpreter2", rpm: "libcairo-script-interpreter2~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo-script-interpreter2-debuginfo", rpm: "libcairo-script-interpreter2-debuginfo~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo2", rpm: "libcairo2~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo2-32bit", rpm: "libcairo2-32bit~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo2-debuginfo", rpm: "libcairo2-debuginfo~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcairo2-debuginfo-32bit", rpm: "libcairo2-debuginfo-32bit~1.15.2~25.3.2", rls: "SLES12.0SP3" ) )){
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

