if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876323" );
	script_version( "2019-05-17T10:04:07+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-17 10:04:07 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-08 02:10:53 +0000 (Wed, 08 May 2019)" );
	script_name( "Fedora Update for perl-YAML FEDORA-2019-1911b73cee" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-1911b73cee" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MKJQXJGMWYVDZSQFDB4EJ2WNJ6RU65J4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-YAML'
  package(s) announced via the FEDORA-2019-1911b73cee advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The YAML.pm module implements a YAML Loader and Dumper based on the YAML 1.0
specification. YAML is a generic data serialization
language that is optimized for human readability. It can be used to express the
data structures of most modern programming languages, including Perl.  For
information on the YAML syntax, please refer to the YAML specification." );
	script_tag( name: "affected", value: "'perl-YAML' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "perl-YAML", rpm: "perl-YAML~1.28~1.fc30", rls: "FC30" ) )){
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

