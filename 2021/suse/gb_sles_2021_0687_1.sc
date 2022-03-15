if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0687.1" );
	script_cve_id( "CVE-2020-36241" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:42 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0687-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0687-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210687-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-autoar' package(s) announced via the SUSE-SU-2021:0687-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gnome-autoar fixes the following issues:

CVE-2020-36241: Skip problematic files that might be extracted outside
 of the destination dir to prevent potential directory traversal
 (bsc#1181930)." );
	script_tag( name: "affected", value: "'gnome-autoar' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "gnome-autoar-debuginfo", rpm: "gnome-autoar-debuginfo~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-autoar-debugsource", rpm: "gnome-autoar-debugsource~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnome-autoar-devel", rpm: "gnome-autoar-devel~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnome-autoar-0-0", rpm: "libgnome-autoar-0-0~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnome-autoar-0-0-debuginfo", rpm: "libgnome-autoar-0-0-debuginfo~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnome-autoar-gtk-0-0", rpm: "libgnome-autoar-gtk-0-0~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnome-autoar-gtk-0-0-debuginfo", rpm: "libgnome-autoar-gtk-0-0-debuginfo~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GnomeAutoar-0_1", rpm: "typelib-1_0-GnomeAutoar-0_1~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GnomeAutoarGtk-0_1", rpm: "typelib-1_0-GnomeAutoarGtk-0_1~0.2.3~3.3.1", rls: "SLES15.0SP2" ) )){
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

