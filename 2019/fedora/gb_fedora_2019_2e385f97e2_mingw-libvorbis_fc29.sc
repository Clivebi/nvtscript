if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875947" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2017-11333", "CVE-2017-11735", "CVE-2017-14160", "CVE-2017-14632", "CVE-2017-14633", "CVE-2018-5146", "CVE-2018-10392", "CVE-2018-10393" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 20:26:00 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:29:16 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for mingw-libvorbis FEDORA-2019-2e385f97e2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-2e385f97e2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7LMKDBAKXCTXK2PG6XESIGC7ZP4742RA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-libvorbis'
  package(s) announced via the FEDORA-2019-2e385f97e2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ogg Vorbis is a fully open, non-proprietary, patent- and royalty-free,
general-purpose compressed audio format for audio and music at fixed
and variable bitrates from 16 to 128 kbps/channel.

This package contains the MinGW Windows cross compiled libvorbis library." );
	script_tag( name: "affected", value: "'mingw-libvorbis' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-libvorbis", rpm: "mingw-libvorbis~1.3.6~2.fc29", rls: "FC29" ) )){
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

