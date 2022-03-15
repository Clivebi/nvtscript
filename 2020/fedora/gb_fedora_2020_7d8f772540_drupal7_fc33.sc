if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878663" );
	script_version( "2021-07-15T11:00:44+0000" );
	script_cve_id( "CVE-2020-13666", "CVE-2020-13671" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-15 11:00:44 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-15 04:15:00 +0000 (Tue, 15 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-27 04:12:04 +0000 (Fri, 27 Nov 2020)" );
	script_name( "Fedora: Security Advisory for drupal7 (FEDORA-2020-7d8f772540)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-7d8f772540" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y663FLPIX3Z3GFILDR2PBK76EFS432DO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7'
  package(s) announced via the FEDORA-2020-7d8f772540 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Equipped with a powerful blend of features, Drupal is a Content Management
System written in PHP that can support a variety of websites ranging from
personal weblogs to large community-driven websites.  Drupal is highly
configurable, skinnable, and secure." );
	script_tag( name: "affected", value: "'drupal7' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7", rpm: "drupal7~7.74~1.fc33", rls: "FC33" ) )){
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

