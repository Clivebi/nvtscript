if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878786" );
	script_version( "2021-01-12T06:51:19+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-12 06:51:19 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:59:07 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Fedora: Security Advisory for tor (FEDORA-2020-3b4dfd9df8)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-3b4dfd9df8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VPC66DTATNACWYQWTB3MDDM4OCRMZQIY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tor'
  package(s) announced via the FEDORA-2020-3b4dfd9df8 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Tor network is a group of volunteer-operated servers that allows people to
improve their privacy and security on the Internet. Tor&#39, s users employ this
network by connecting through a series of virtual tunnels rather than making a
direct connection, thus allowing both organizations and individuals to share
information over public networks without compromising their privacy. Along the
same line, Tor is an effective censorship circumvention tool, allowing its
users to reach otherwise blocked destinations or content. Tor can also be used
as a building block for software developers to create new communication tools
with built-in privacy features.

This package contains the Tor software that can act as either a server on the
Tor network, or as a client to connect to the Tor network." );
	script_tag( name: "affected", value: "'tor' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "tor", rpm: "tor~0.4.4.6~1.fc33", rls: "FC33" ) )){
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

