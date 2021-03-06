if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877572" );
	script_version( "2020-03-16T11:42:10+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-16 11:42:10 +0000 (Mon, 16 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-15 04:04:56 +0000 (Sun, 15 Mar 2020)" );
	script_name( "Fedora: Security Advisory for mediawiki (FEDORA-2020-d24bd1cad3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-d24bd1cad3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4P2LAU7BV6DPHP3UWB43DEETPOANHAYV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediawiki'
  package(s) announced via the FEDORA-2020-d24bd1cad3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MediaWiki is the software used for Wikipedia and the other Wikimedia
Foundation websites. Compared to other wikis, it has an excellent
range of features and support for high-traffic websites using multiple
servers

This package supports wiki farms. Read the instructions for creating wiki
instances under /usr/share/doc/mediawiki/README.RPM.
Remember to remove the config dir after completing the configuration." );
	script_tag( name: "affected", value: "'mediawiki' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mediawiki", rpm: "mediawiki~1.32.6~1.fc30", rls: "FC30" ) )){
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

