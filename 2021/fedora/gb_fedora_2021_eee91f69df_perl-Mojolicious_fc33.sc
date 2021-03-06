if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879817" );
	script_version( "2021-07-23T08:38:39+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 08:38:39 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-11 03:22:13 +0000 (Sun, 11 Jul 2021)" );
	script_name( "Fedora: Security Advisory for perl-Mojolicious (FEDORA-2021-eee91f69df)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-eee91f69df" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GYAPOOAOIZUZXKYWNO6SBAA47CZJ42KQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-Mojolicious'
  package(s) announced via the FEDORA-2021-eee91f69df advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Back in the early days of the web there was this wonderful Perl library
called CGI, many people only learned Perl because of it. It was simple
enough to get started without knowing much about the language and powerful
enough to keep you going, learning by doing was much fun. While most of the
techniques used are outdated now, the idea behind it is not. Mojolicious is
a new attempt at implementing this idea using state of the art technology." );
	script_tag( name: "affected", value: "'perl-Mojolicious' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-Mojolicious", rpm: "perl-Mojolicious~8.73~2.fc33", rls: "FC33" ) )){
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

