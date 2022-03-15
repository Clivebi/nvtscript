if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879896" );
	script_version( "2021-08-03T06:52:21+0000" );
	script_cve_id( "CVE-2021-3602" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-03 06:52:21 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:18:12 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Fedora: Security Advisory for buildah (FEDORA-2021-440e34200c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-440e34200c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CAYDF5STQQ2MWYFKJISEVKKCDRW6K3MP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'buildah'
  package(s) announced via the FEDORA-2021-440e34200c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The buildah package provides a command line tool which can be used to

  * create a working container from scratch
or

  * create a working container from an image as a starting point

  * mount/umount a working container&#39, s root file system for manipulation

  * save container&#39, s root file system layer to create a new image

  * delete a working container or an image" );
	script_tag( name: "affected", value: "'buildah' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "buildah", rpm: "buildah~1.21.4~4.fc34", rls: "FC34" ) )){
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

