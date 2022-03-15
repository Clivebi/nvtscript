if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876498" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-10152" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 14:11:00 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-06-15 02:09:58 +0000 (Sat, 15 Jun 2019)" );
	script_name( "Fedora Update for podman FEDORA-2019-b66d704846" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-b66d704846" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PDEYSUQVJPS3VPJGSC433TRRS2EMGDMY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'podman' package(s) announced via the FEDORA-2019-b66d704846 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "podman (Pod Manager) is a fully featured
  container engine that is a simple daemonless tool.  podman provides a Docker-CLI
  comparable command line that eases the transition from other container engines
  and allows the management of pods, containers and images.  Simply put: alias
  docker=podman.  Most podman commands can be run as a regular user, without
  requiring additional privileges.

podman uses Buildah(1) internally to create container images. Both tools share image (not
container) storage, hence each can use or manipulate images (but not containers) created
by the other.

Manage Pods, Containers and Container Images
libpod Simple management tool for pods, containers and images" );
	script_tag( name: "affected", value: "'podman' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "podman", rpm: "podman~1.4.0~2.fc29", rls: "FC29" ) )){
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

