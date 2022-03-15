if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892582" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2019-0222" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-06 12:56:00 +0000 (Tue, 06 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-06 04:00:07 +0000 (Sat, 06 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for mqtt-client (DLA-2582-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00004.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2582-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2582-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/925964" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mqtt-client'
  package(s) announced via the DLA-2582-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in mqtt-client where unmarshalling
corrupt MQTT frame can lead to broker Out of Memory exception making
it unresponsive." );
	script_tag( name: "affected", value: "'mqtt-client' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.14-1+deb9u1.

We recommend that you upgrade your mqtt-client packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmqtt-client-java", ver: "1.14-1+deb9u1", rls: "DEB9" ) )){
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

