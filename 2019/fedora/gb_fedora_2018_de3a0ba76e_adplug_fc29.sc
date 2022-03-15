if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876060" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_cve_id( "CVE-2018-17825" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-14 04:15:00 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:33:29 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for adplug FEDORA-2018-de3a0ba76e" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2018-de3a0ba76e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HKXBANJN5Q6CIMHFEFVA7RKCSGWF6WC2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'adplug'
  package(s) announced via the FEDORA-2018-de3a0ba76e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "AdPlug is a free software, cross-platform, hardware independent AdLib
sound player library, mainly written in C++ and released under the
LGPL. AdPlug plays sound data, originally created for the AdLib (OPL2)
audio board, directly from its original format on top of an OPL2
emulator or by using the real hardware. No OPL chip is required for
playback. It supports various audio formats from MS-DOS AdLib trackers." );
	script_tag( name: "affected", value: "'adplug' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "adplug", rpm: "adplug~2.2.1~7.fc29", rls: "FC29" ) )){
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

