if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2709.1" );
	script_cve_id( "CVE-2018-10873", "CVE-2018-10893" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:37 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2709-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2709-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182709-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-gtk' package(s) announced via the SUSE-SU-2018:2709-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spice-gtk fixes the following issues:

Security issues fixed:
CVE-2018-10873: Fix potential heap corruption when demarshalling
 (bsc#1104448)

CVE-2018-10893: Avoid buffer overflow on image lz checks (bsc#1101295)

Other bugs fixed:
Add setuid bit to spice-client-glib-usb-acl-helper (bsc#1101420)" );
	script_tag( name: "affected", value: "'spice-gtk' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Server Applications 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-2_0-8", rpm: "libspice-client-glib-2_0-8~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-2_0-8-debuginfo", rpm: "libspice-client-glib-2_0-8-debuginfo~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-helper", rpm: "libspice-client-glib-helper~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-glib-helper-debuginfo", rpm: "libspice-client-glib-helper-debuginfo~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-gtk-3_0-5", rpm: "libspice-client-gtk-3_0-5~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-client-gtk-3_0-5-debuginfo", rpm: "libspice-client-gtk-3_0-5-debuginfo~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-controller0", rpm: "libspice-controller0~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-controller0-debuginfo", rpm: "libspice-controller0-debuginfo~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-debuginfo", rpm: "spice-gtk-debuginfo~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-debugsource", rpm: "spice-gtk-debugsource~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-gtk-devel", rpm: "spice-gtk-devel~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-SpiceClientGlib-2_0", rpm: "typelib-1_0-SpiceClientGlib-2_0~0.34~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-SpiceClientGtk-3_0", rpm: "typelib-1_0-SpiceClientGtk-3_0~0.34~3.3.1", rls: "SLES15.0" ) )){
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

