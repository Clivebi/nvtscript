if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877917" );
	script_version( "2021-07-19T11:00:51+0000" );
	script_cve_id( "CVE-2019-20797" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-19 11:00:51 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-16 16:15:00 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-07 03:27:47 +0000 (Sun, 07 Jun 2020)" );
	script_name( "Fedora: Security Advisory for prboom-plus (FEDORA-2020-fe80f1f388)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-fe80f1f388" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P3WS7GRZUIHCGLFET33MGC3PEKCH37W6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'prboom-plus'
  package(s) announced via the FEDORA-2020-fe80f1f388 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Doom is a classic 3D shoot-em-up game.
PrBoom+ is a Doom source port developed from the original PrBoom project
by Andrey Budko.
The target of the project is to extend the original port with features
that are necessary or useful." );
	script_tag( name: "affected", value: "'prboom-plus' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "prboom-plus", rpm: "prboom-plus~2.5.1.4~18.fc32", rls: "FC32" ) )){
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
