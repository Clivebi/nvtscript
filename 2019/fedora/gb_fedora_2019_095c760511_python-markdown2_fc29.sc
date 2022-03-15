if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876172" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2018-5773" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-06 13:39:00 +0000 (Tue, 06 Feb 2018)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:37:49 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for python-markdown2 FEDORA-2019-095c760511" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-095c760511" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/SDPYQULVCAMPEXJJIUXMCG3HQIGM7XR3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-markdown2'
  package(s) announced via the FEDORA-2019-095c760511 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Markdown is a text-to-HTML filter, it translates an easy-to-read /
easy-to-write structured text format into HTML. Markdown&#39, s text format
is most similar to that of plain text email, and supports features
such as headers, emphasis, code blocks, blockquotes, and links.

This is a fast and complete Python implementation of the Markdown
spec." );
	script_tag( name: "affected", value: "'python-markdown2' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-markdown2", rpm: "python-markdown2~2.3.7~1.fc29", rls: "FC29" ) )){
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

