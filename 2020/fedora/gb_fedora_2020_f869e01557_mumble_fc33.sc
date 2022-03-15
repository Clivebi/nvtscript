if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878380" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2020-13962" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 19:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-29 03:20:00 +0000 (Tue, 29 Sep 2020)" );
	script_name( "Fedora: Security Advisory for mumble (FEDORA-2020-f869e01557)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-f869e01557" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/V3IZY7LKJ6NAXQDFYFR4S7L5BBHYK53K" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mumble'
  package(s) announced via the FEDORA-2020-f869e01557 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mumble provides low-latency, high-quality voice communication for gamers.
It includes game linking, so voice from other players comes
from the direction of their characters, and has echo
cancellation so that the sound from your loudspeakers
won&#39, t be audible to other players." );
	script_tag( name: "affected", value: "'mumble' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "mumble", rpm: "mumble~1.3.2~1.fc33", rls: "FC33" ) )){
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

