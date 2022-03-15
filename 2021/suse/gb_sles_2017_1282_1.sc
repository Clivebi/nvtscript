if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1282.1" );
	script_cve_id( "CVE-2015-7995", "CVE-2015-9019", "CVE-2016-4738", "CVE-2017-5029" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 20:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1282-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1282-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171282-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxslt' package(s) announced via the SUSE-SU-2017:1282-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxslt fixes the following issues:
- CVE-2017-5029: The xsltAddTextString function in transform.c lacked a
 check for integer overflow during a size calculation, which allowed a
 remote attacker to perform an out of bounds memory write via a crafted
 HTML page (bsc#1035905).
- CVE-2016-4738: Fix heap overread in xsltFormatNumberConversion: An empty
 decimal-separator could cause a heap overread. This can be exploited to
 leak a couple of bytes after the buffer that holds the pattern string
 (bsc#1005591).
- CVE-2015-9019: Properly initialize random generator (bsc#934119).
- CVE-2015-7995: Vulnerability in function xsltStylePreCompute' in
 preproc.c could cause a type confusion leading to DoS. (bsc#952474)" );
	script_tag( name: "affected", value: "'libxslt' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libxslt", rpm: "libxslt~1.1.24~19.33.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt-32bit", rpm: "libxslt-32bit~1.1.24~19.33.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxslt-x86", rpm: "libxslt-x86~1.1.24~19.33.1", rls: "SLES11.0SP4" ) )){
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

