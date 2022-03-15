if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850951" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 14:56:42 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2014-0503", "CVE-2014-0504" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for flash-player (SUSE-SU-2014:0387-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Adobe Flash Player was updated to version 11.2.202.346 to
  fix security  issues:

  * CVE-2014-0503: A vulnerability that could be used to
  bypass the same origin policy was fixed.

  * CVE-2014-0504: A vulnerability that could be used to
  read the contents of the clipboard was fixed.

    Security Issues references:

  * CVE-2014-0503

  * CVE-2014-0504" );
	script_tag( name: "affected", value: "flash-player on SUSE Linux Enterprise Desktop 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:0387-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLED11\\.0SP3" );
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
if(release == "SLED11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "flash-player", rpm: "flash-player~11.2.202.346~0.3.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flash-player-gnome", rpm: "flash-player-gnome~11.2.202.346~0.3.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "flash-player-kde4", rpm: "flash-player-kde4~11.2.202.346~0.3.1", rls: "SLED11.0SP3" ) )){
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

