if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877812" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2020-11722" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-25 00:15:00 +0000 (Sat, 25 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-05-11 03:22:24 +0000 (Mon, 11 May 2020)" );
	script_name( "Fedora: Security Advisory for crawl (FEDORA-2020-c976cfa87e)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-c976cfa87e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XNXK7QE7EA7XSDDNOWX2A6MJNWOIYCTC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'crawl'
  package(s) announced via the FEDORA-2020-c976cfa87e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This is the Console (ncurses) version of crawl.

Dungeon Crawl Stone Soup is a free roguelike game of exploration
and treasure-hunting in dungeons filled with dangerous and unfriendly
monsters in a quest for the mystifyingly fabulous Orb of Zot.

Dungeon Crawl Stone Soup has diverse species and many different character
backgrounds to choose from, deep tactical game-play, sophisticated magic,
religion and skill systems, and a grand variety of monsters to fight and
run from, making each game unique and challenging." );
	script_tag( name: "affected", value: "'crawl' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "crawl", rpm: "crawl~0.24.1~2.fc32", rls: "FC32" ) )){
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

