if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878474" );
	script_version( "2021-07-14T11:00:55+0000" );
	script_cve_id( "CVE-2020-25862", "CVE-2020-25863", "CVE-2020-25866" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-14 11:00:55 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-10 20:20:00 +0000 (Wed, 10 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-10-18 03:08:57 +0000 (Sun, 18 Oct 2020)" );
	script_name( "Fedora: Security Advisory for wireshark (FEDORA-2020-1b390bec14)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-1b390bec14" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6IGRYKW4XLR44YDWTAH547ODYYBYPB2D" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the FEDORA-2020-1b390bec14 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Wireshark allows you to examine protocol data stored in files or as it is
captured from wired or wireless (WiFi or Bluetooth) networks, USB devices,
and many other sources.  It supports dozens of protocol capture file formats
and understands more than a thousand protocols.

It has many powerful features including a rich display filter language
and the ability to reassemble multiple protocol packets in order to, for
example, view a complete TCP stream, save the contents of a file which was
transferred over HTTP or CIFS, or play back an RTP audio stream." );
	script_tag( name: "affected", value: "'wireshark' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~3.2.7~1.fc31", rls: "FC31" ) )){
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

