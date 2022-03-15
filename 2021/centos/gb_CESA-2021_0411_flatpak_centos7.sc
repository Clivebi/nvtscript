if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883324" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-21261" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-27 19:34:00 +0000 (Wed, 27 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-02-10 04:01:42 +0000 (Wed, 10 Feb 2021)" );
	script_name( "CentOS: Security Advisory for flatpak (CESA-2021:0411)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:0411" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-February/048272.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flatpak'
  package(s) announced via the CESA-2021:0411 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Flatpak is a system for building, distributing, and running sandboxed
desktop applications on Linux.

Security Fix(es):

  * flatpak: sandbox escape via spawn portal (CVE-2021-21261)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'flatpak' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "flatpak", rpm: "flatpak~1.0.9~10.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-builder", rpm: "flatpak-builder~1.0.0~10.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-devel", rpm: "flatpak-devel~1.0.9~10.el7_9", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flatpak-libs", rpm: "flatpak-libs~1.0.9~10.el7_9", rls: "CentOS7" ) )){
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

