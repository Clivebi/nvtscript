if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878901" );
	script_version( "2021-02-12T05:36:42+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 05:36:42 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-08 04:08:37 +0000 (Mon, 08 Feb 2021)" );
	script_name( "Fedora: Security Advisory for python-pygments (FEDORA-2021-33abbae37b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-33abbae37b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RZGJ3S4TSKRDVFCLUEEGHO4TBKBYWE5U" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pygments'
  package(s) announced via the FEDORA-2021-33abbae37b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Pygments is a generic syntax highlighter for general use in all kinds
of software such as forum systems, wikis or other applications that
need to prettify source code. Highlights are:

  * a wide range of common languages and markup formats is supported

  * special attention is paid to details that increase highlighting
    quality

  * support for new languages and formats are added easily, most
    languages use a simple regex-based lexing mechanism

  * a number of output formats is available, among them HTML, RTF,
    LaTeX and ANSI sequences

  * it is usable as a command-line tool and as a library

  * ... and it highlights even Brainf*ck!" );
	script_tag( name: "affected", value: "'python-pygments' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-pygments", rpm: "python-pygments~2.4.2~8.fc32", rls: "FC32" ) )){
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

