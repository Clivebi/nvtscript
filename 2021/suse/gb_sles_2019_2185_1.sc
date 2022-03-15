if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2185.1" );
	script_cve_id( "CVE-2019-11460", "CVE-2019-11461", "CVE-2019-8308" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-27 17:29:00 +0000 (Mon, 27 May 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2185-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2185-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192185-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flatpak' package(s) announced via the SUSE-SU-2019:2185-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for flatpak fixes the following issues:

Security issues fixed:
CVE-2019-8308: Fixed a potential sandbox escape via /proc (bsc#1125431).

CVE-2019-11460: Fixed a compromised thumbnailer may escape the
 bubblewrap sandbox used to confine thumbnailers by using the TIOCSTI
 ioctl (bsc#1133043).

CVE-2019-11461: Fixed a compromised thumbnailer may escape the
 bubblewrap sandbox used to confine thumbnailers by using the TIOCSTI
 ioctl (bsc#1133041)." );
	script_tag( name: "affected", value: "'flatpak' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "flatpak", rpm: "flatpak~0.10.4~4.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-debuginfo", rpm: "flatpak-debuginfo~0.10.4~4.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-debugsource", rpm: "flatpak-debugsource~0.10.4~4.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-devel", rpm: "flatpak-devel~0.10.4~4.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libflatpak0", rpm: "libflatpak0~0.10.4~4.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libflatpak0-debuginfo", rpm: "libflatpak0-debuginfo~0.10.4~4.10.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Flatpak-1_0", rpm: "typelib-1_0-Flatpak-1_0~0.10.4~4.10.1", rls: "SLES15.0" ) )){
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

