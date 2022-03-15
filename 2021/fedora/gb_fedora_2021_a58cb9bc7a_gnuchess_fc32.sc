if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879378" );
	script_version( "2021-08-20T12:01:13+0000" );
	script_cve_id( "CVE-2021-30184" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 12:01:13 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-17 03:05:13 +0000 (Sat, 17 Apr 2021)" );
	script_name( "Fedora: Security Advisory for gnuchess (FEDORA-2021-a58cb9bc7a)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-a58cb9bc7a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XXOTMUSBVUZNA3JMPG6BU37DQW2YOJWS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnuchess'
  package(s) announced via the FEDORA-2021-a58cb9bc7a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The gnuchess package contains the GNU chess program.  By default,
GNU chess uses a curses text-based interface.  Alternatively, GNU chess
can be used in conjunction with the xboard user interface and the X
Window System for play using a graphical chess board.

Install the gnuchess package if you would like to play chess on your
computer.  If you&#39, d like to use a graphical interface with GNU chess,
you&#39, ll also need to install the xboard package and the X Window System." );
	script_tag( name: "affected", value: "'gnuchess' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnuchess", rpm: "gnuchess~6.2.7~5.fc32", rls: "FC32" ) )){
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

