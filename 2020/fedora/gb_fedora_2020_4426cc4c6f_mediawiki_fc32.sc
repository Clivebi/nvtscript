if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877662" );
	script_version( "2020-04-07T12:33:10+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-07 12:33:10 +0000 (Tue, 07 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-04 03:12:34 +0000 (Sat, 04 Apr 2020)" );
	script_name( "Fedora: Security Advisory for mediawiki (FEDORA-2020-4426cc4c6f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-4426cc4c6f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3MTA5D2C47VEPEKAATESU4OERD4YEMFU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediawiki'
  package(s) announced via the FEDORA-2020-4426cc4c6f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MediaWiki is the software used for Wikipedia and the other Wikimedia
Foundation websites. Compared to other wikis, it has an excellent
range of features and support for high-traffic websites using multiple
servers

This package supports wiki farms. Read the instructions for creating wiki
instances under /usr/share/doc/mediawiki/README.RPM.
Remember to remove the config dir after completing the configuration." );
	script_tag( name: "affected", value: "'mediawiki' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "mediawiki", rpm: "mediawiki~1.33.3~1.fc32", rls: "FC32" ) )){
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

