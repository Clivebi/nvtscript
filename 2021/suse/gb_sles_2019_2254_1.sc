if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2254.1" );
	script_cve_id( "CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9516", "CVE-2019-9517", "CVE-2019-9518" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:36:00 +0000 (Sat, 30 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2254-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2254-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192254-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2019:2254-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs10 to version 10.16.3 fixes the following issues:

Security issues fixed:
CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
 window size manipulation and stream prioritization manipulation,
 potentially leading to a denial of service (bsc#1146091).

CVE-2019-9512: Fixed HTTP/2 flood using PING frames results in unbounded
 memory growth (bsc#1146099).

CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
 resource loops, potentially leading to a denial of service.
 (bsc#1146094).

CVE-2019-9514: Fixed HTTP/2 implementation that is vulnerable to a reset
 flood, potentially leading to a denial of service (bsc#1146095).

CVE-2019-9515: Fixed HTTP/2 flood using SETTINGS frames results in
 unbounded memory growth (bsc#1146100).

CVE-2019-9516: Fixed HTTP/2 implementation that is vulnerable to a
 header leak, potentially leading to a denial of service (bsc#1146090).

CVE-2019-9517: Fixed HTTP/2 implementations that are vulnerable to
 unconstrained interal data buffering (bsc#1146097).

CVE-2019-9518: Fixed HTTP/2 implementation that is vulnerable to a flood
 of empty frames, potentially leading to a denial of service
 (bsc#1146093)." );
	script_tag( name: "affected", value: "'nodejs10' package(s) on SUSE Linux Enterprise Module for Web Scripting 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs10", rpm: "nodejs10~10.16.3~1.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debuginfo", rpm: "nodejs10-debuginfo~10.16.3~1.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-debugsource", rpm: "nodejs10-debugsource~10.16.3~1.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-devel", rpm: "nodejs10-devel~10.16.3~1.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs10-docs", rpm: "nodejs10-docs~10.16.3~1.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm10", rpm: "npm10~10.16.3~1.12.1", rls: "SLES12.0" ) )){
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

