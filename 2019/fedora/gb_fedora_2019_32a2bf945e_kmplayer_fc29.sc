if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876804" );
	script_version( "2021-09-02T08:01:23+0000" );
	script_cve_id( "CVE-2019-9133" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-17 03:15:00 +0000 (Tue, 17 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-17 02:22:37 +0000 (Tue, 17 Sep 2019)" );
	script_name( "Fedora Update for kmplayer FEDORA-2019-32a2bf945e" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-32a2bf945e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4D55BLGBNWNIMNI5N57WDPAFQCUIM6XX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kmplayer'
  package(s) announced via the FEDORA-2019-32a2bf945e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "KMPlayer, a simple front-end for MPlayer/FFMpeg/Phonon.
It can play DVD/VCD movies, from file or URL and from a video device.
KMPlayer can embed inside Konqueror. Which means if you click
on a movie file, the movie is played inside Konqueror." );
	script_tag( name: "affected", value: "'kmplayer' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "kmplayer", rpm: "kmplayer~0.12.0b~1.fc29", rls: "FC29" ) )){
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
