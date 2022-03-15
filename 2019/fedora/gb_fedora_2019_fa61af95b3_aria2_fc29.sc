if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876065" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2019-3500" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 18:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:33:33 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for aria2 FEDORA-2019-fa61af95b3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-fa61af95b3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U5OLPTVYHJZJ2MVEXJCNPXBSFPVPE4XX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aria2'
  package(s) announced via the FEDORA-2019-fa61af95b3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "aria2 is a download utility with resuming and segmented downloading.
Supported protocols are HTTP/HTTPS/FTP/BitTorrent. It also supports Metalink
version 3.0.

Currently it has following features:

  - HTTP/HTTPS GET support

  - HTTP Proxy support

  - HTTP BASIC authentication support

  - HTTP Proxy authentication support

  - FTP support(active, passive mode)

  - FTP through HTTP proxy(GET command or tunneling)

  - Segmented download

  - Cookie support

  - It can run as a daemon process.

  - BitTorrent protocol support with fast extension.

  - Selective download in multi-file torrent

  - Metalink version 3.0 support(HTTP/FTP/BitTorrent).

  - Limiting download/upload speed" );
	script_tag( name: "affected", value: "'aria2' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "aria2", rpm: "aria2~1.34.0~4.fc29", rls: "FC29" ) )){
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

