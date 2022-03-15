if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878686" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2020-14360", "CVE-2020-25712" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-26 18:29:00 +0000 (Tue, 26 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-12-05 04:11:11 +0000 (Sat, 05 Dec 2020)" );
	script_name( "Fedora: Security Advisory for xorg-x11-server (FEDORA-2020-c8a7df24d4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-c8a7df24d4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XE74JTV4TIKEIDUQP45LYBIONHOG55WY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-server'
  package(s) announced via the FEDORA-2020-c8a7df24d4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "X.Org X11 X server" );
	script_tag( name: "affected", value: "'xorg-x11-server' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~1.20.10~1.fc32", rls: "FC32" ) )){
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

