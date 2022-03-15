if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878445" );
	script_version( "2021-07-15T11:00:44+0000" );
	script_cve_id( "CVE-2020-5238" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-15 11:00:44 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-06 18:15:00 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-07 03:09:31 +0000 (Wed, 07 Oct 2020)" );
	script_name( "Fedora: Security Advisory for ghc-cmark-gfm (FEDORA-2020-1eaffe0013)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-1eaffe0013" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GFYLQEQUK7RJB4RDOHKMWMAOQHW4ATLY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghc-cmark-gfm'
  package(s) announced via the FEDORA-2020-1eaffe0013 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Flavored Markdown>, a fully specified variant of Markdown. It includes sources
for libcmark-gfm (0.29.0.gfm.0) and does not require prior installation of the
C library." );
	script_tag( name: "affected", value: "'ghc-cmark-gfm' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "ghc-cmark-gfm", rpm: "ghc-cmark-gfm~0.2.2~1.fc32", rls: "FC32" ) )){
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

