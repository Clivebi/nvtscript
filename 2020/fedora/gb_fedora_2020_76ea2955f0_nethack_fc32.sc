if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877598" );
	script_version( "2020-03-20T06:19:59+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-20 06:19:59 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-19 04:07:10 +0000 (Thu, 19 Mar 2020)" );
	script_name( "Fedora: Security Advisory for nethack (FEDORA-2020-76ea2955f0)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-76ea2955f0" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VL4KIRJ35J5WF74THWVJO2JRTHA37QJG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nethack'
  package(s) announced via the FEDORA-2020-76ea2955f0 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NetHack is a single player dungeon exploration game that runs on a
wide variety of computer systems, with a variety of graphical and text
interfaces all using the same game engine.

Unlike many other Dungeons & Dragons-inspired games, the emphasis in
NetHack is on discovering the detail of the dungeon and not simply
killing everything in sight - in fact, killing everything in sight is
a good way to die quickly.

Each game presents a different landscape - the random number generator
provides an essentially unlimited number of variations of the dungeon
and its denizens to be discovered by the player in one of a number of
characters: you can pick your race, your role, and your gender." );
	script_tag( name: "affected", value: "'nethack' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "nethack", rpm: "nethack~3.6.6~1.fc32", rls: "FC32" ) )){
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

