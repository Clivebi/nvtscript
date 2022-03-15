if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879927" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-34558" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 14:15:00 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 03:13:13 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Fedora: Security Advisory for podman (FEDORA-2021-6ac9b98f9e)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6ac9b98f9e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LBMLUQMN6XRKPVOI5XFFBP4XSR7RNTYR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'podman'
  package(s) announced via the FEDORA-2021-6ac9b98f9e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "podman (Pod Manager) is a fully featured container engine that is a simple
daemonless tool.  podman provides a Docker-CLI comparable command line that
eases the transition from other container engines and allows the management of
pods, containers and images.  Simply put: alias docker=podman.
Most podman commands can be run as a regular user, without requiring
additional privileges.

podman uses Buildah(1) internally to create container images.
Both tools share image (not container) storage, hence each can use or
manipulate images (but not containers) created by the other.

Manage Pods, Containers and Container Images
podman Simple management tool for pods, containers and images" );
	script_tag( name: "affected", value: "'podman' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "podman", rpm: "podman~3.2.3~2.fc33", rls: "FC33" ) )){
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

