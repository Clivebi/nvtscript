if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878434" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2020-5238" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-06 18:15:00 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-07 03:09:24 +0000 (Wed, 07 Oct 2020)" );
	script_name( "Fedora: Security Advisory for gitit (FEDORA-2020-fe299b3fa3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-fe299b3fa3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UKE5RWESQBEGZN5S4UDVW3VW2KN3PKV2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gitit'
  package(s) announced via the FEDORA-2020-fe299b3fa3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Gitit is a wiki backed by a git, darcs, or mercurial filestore. Pages and
uploaded files can be modified either directly via the VCS&#39, s command-line tools
or through the wiki&#39, s web interface. Pandoc is used for markup processing, so
pages may be written in (extended) markdown, reStructuredText, LaTeX, HTML, or
literate Haskell, and exported in ten different formats, including LaTeX,
ConTeXt, DocBook, RTF, OpenOffice ODT, and MediaWiki markup.

Notable features include

  * plugins: dynamically loaded page transformations written in Haskell (see
'Network.Gitit.Interface')

  * conversion of TeX math to MathML for display in web browsers

  * syntax highlighting of source code files and code snippets

  * Atom feeds (site-wide and per-page)

  * a library, 'Network.Gitit', that makes it simple to include a gitit wiki in
any happstack application" );
	script_tag( name: "affected", value: "'gitit' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "gitit", rpm: "gitit~0.12.3.2~4.fc31", rls: "FC31" ) )){
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

