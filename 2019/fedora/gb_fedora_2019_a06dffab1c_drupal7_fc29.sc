if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876342" );
	script_version( "2019-05-14T05:04:40+0000" );
	script_cve_id( "CVE-2019-11358", "CVE-2012-2922" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-14 05:04:40 +0000 (Tue, 14 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-10 02:11:35 +0000 (Fri, 10 May 2019)" );
	script_name( "Fedora Update for drupal7 FEDORA-2019-a06dffab1c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-a06dffab1c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QV3PKZC3PQCO3273HAT76PAQZFBEO4KP" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'drupal7' package(s) announced via the FEDORA-2019-a06dffab1c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Equipped with a powerful blend of features,
  Drupal is a Content Management System written in PHP that can support a
  variety of websites ranging from personal weblogs to large community-driven
  websites.  Drupal is highly configurable, skinnable, and secure." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7", rpm: "drupal7~7.66~1.fc29", rls: "FC29" ) )){
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

