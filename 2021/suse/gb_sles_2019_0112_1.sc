if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0112.1" );
	script_cve_id( "CVE-2018-17097", "CVE-2018-17098" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-08 19:35:00 +0000 (Thu, 08 Nov 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0112-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0112-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190112-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'soundtouch' package(s) announced via the SUSE-SU-2019:0112-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for soundtouch fixes the following issues:

Security issues fixed:
CVE-2018-17098: Fixed a heap corruption from size inconsistency, which
 allowed remote attackers to cause a denial of service or possibly have
 other unspecified impact (bsc#1108632)

CVE-2018-17097: Fixed a double free, which allowed remote attackers to
 cause a denial of service or possibly have other unspecified impact
 (bsc#1108631)" );
	script_tag( name: "affected", value: "'soundtouch' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0", rpm: "libSoundTouch0~1.8.0~3.11.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSoundTouch0-debuginfo", rpm: "libSoundTouch0-debuginfo~1.8.0~3.11.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-debuginfo", rpm: "soundtouch-debuginfo~1.8.0~3.11.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-debugsource", rpm: "soundtouch-debugsource~1.8.0~3.11.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "soundtouch-devel", rpm: "soundtouch-devel~1.8.0~3.11.1", rls: "SLES15.0" ) )){
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

