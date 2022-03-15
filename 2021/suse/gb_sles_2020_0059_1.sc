if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0059.1" );
	script_cve_id( "CVE-2019-13173", "CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9516", "CVE-2019-9517", "CVE-2019-9518" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0059-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0059-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200059-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs12' package(s) announced via the SUSE-SU-2020:0059-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs12 fixes the following issues:

Update to LTS release 12.13.0 (jsc#SLE-8947).

Security issues fixed:
CVE-2019-9511: Fixed the HTTP/2 implementation that was vulnerable to
 window size manipulations (bsc#1146091).

CVE-2019-9512: Fixed the HTTP/2 implementation that was vulnerable to
 floods using PING frames (bsc#1146099).

CVE-2019-9513: Fixed the HTTP/2 implementation that was vulnerable to
 resource loops, potentially leading to a denial of service (bsc#1146094).

CVE-2019-9514: Fixed the HTTP/2 implementation that was vulnerable to a
 reset flood, potentially leading to a denial of service (bsc#1146095).

CVE-2019-9515: Fixed the HTTP/2 implementation that was vulnerable to a
 SETTINGS frame flood (bsc#1146100).

CVE-2019-9516: Fixed the HTTP/2 implementation that was vulnerable to a
 header leak, potentially leading to a denial of service (bsc#1146090).

CVE-2019-9517: Fixed the HTTP/2 implementation that was vulnerable to
 unconstrained interal data buffering (bsc#1146097).

CVE-2019-9518: Fixed the HTTP/2 implementation that was vulnerable to a
 flood of empty frames, potentially leading to a denial of service
 (bsc#1146093).

CVE-2019-13173: Fixed a file overwrite in the fstream.DirWriter()
 function (bsc#1140290)." );
	script_tag( name: "affected", value: "'nodejs12' package(s) on SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs12", rpm: "nodejs12~12.13.0~1.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debuginfo", rpm: "nodejs12-debuginfo~12.13.0~1.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debugsource", rpm: "nodejs12-debugsource~12.13.0~1.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-devel", rpm: "nodejs12-devel~12.13.0~1.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-docs", rpm: "nodejs12-docs~12.13.0~1.3.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm12", rpm: "npm12~12.13.0~1.3.1", rls: "SLES12.0" ) )){
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

